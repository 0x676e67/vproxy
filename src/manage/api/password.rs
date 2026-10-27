//! Self-service password changes for this process's authenticated administrator.
//! No target identity comes from JSON; proxy and node credentials are unrelated.

use super::*;
use crate::manage::store::{self, administrators::PasswordChangeOutcome};

// Each decoded password is still at most 1024 UTF-8 bytes. JSON may spell every
// ASCII byte as six bytes (\u0061), so two valid fields exceed the usual 4 KiB.
const MAX_PASSWORD_JSON_BYTES: usize = 16 * 1024;

/// No Debug/Serialize implementations: neither field may enter generic tracing.
/// Deserializing each field into Zeroizing also clears partially decoded input
/// when a later field or strict unknown-field check rejects the object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    #[serde(deserialize_with = "secret")]
    current_password: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    new_password: Zeroizing<String>,
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// The short-lived request identity is not authority after blocking hashing.
/// Session, CSRF and generation are rechecked when entering the mutation fence.
struct Attempt {
    token: String,
    csrf: String,
    administrator: AdministratorView,
    generation: u64,
}

fn attempt(state: &AppState, headers: &HeaderMap, address: IpAddr) -> Result<Attempt, ApiError> {
    let token = session_cookie(headers)?.ok_or_else(ApiError::authentication_required)?;
    let csrf = single_header(headers, header::HeaderName::from_static("x-csrf-token"))?
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"))?;
    let mut security = state.security()?;
    let session = security.session(token, Instant::now())?;
    if !bool::from(session.csrf_token.as_bytes().ct_eq(csrf.as_bytes())) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "invalid_csrf"));
    }
    let administrator = session.administrator.clone();
    if security.password_change_pending {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_busy",
        ));
    }
    if !security.allow_login(address, Instant::now()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "login_rate_limited",
        ));
    }
    Ok(Attempt {
        token: token.to_owned(),
        csrf: csrf.to_owned(),
        administrator,
        generation: security.login_generation,
    })
}

impl SecurityState {
    /// Revalidate authority and advance before revoking sessions, without any
    /// SQL, Argon2 or await under the mutex. Generation exhaustion changes nothing.
    fn begin_password_change(&mut self, attempt: &Attempt) -> Result<u64, ApiError> {
        if self.password_change_pending {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_busy",
            ));
        }
        if self.login_generation != attempt.generation {
            return Err(ApiError::authentication_required());
        }
        let session = self.session(&attempt.token, Instant::now())?;
        if session.administrator.id != attempt.administrator.id
            || !bool::from(session.csrf_token.as_bytes().ct_eq(attempt.csrf.as_bytes()))
        {
            return Err(ApiError::authentication_required());
        }
        let generation = self
            .login_generation
            .checked_add(1)
            .ok_or_else(ApiError::internal)?;
        self.login_generation = generation;
        self.password_change_pending = true;
        self.sessions
            .retain(|_, session| session.administrator.id != attempt.administrator.id);
        Ok(generation)
    }

    /// Clearing pending admits only fresh-generation logins, never resurrects
    /// revoked sessions. Unknown outcomes deliberately do not call this method.
    fn finish_password_change(&mut self, generation: u64) -> Result<(), ApiError> {
        if !self.password_change_pending || self.login_generation != generation {
            return Err(ApiError::internal());
        }
        self.password_change_pending = false;
        Ok(())
    }
}

/// The owned permit, update gate and AppState (including author ownership) live
/// in the blocking operation, not its cancellable HTTP waiter. No browser
/// disconnect or timeout can release capacity midway through commit/fencing.
fn perform(state: &AppState, attempt: Attempt, input: PasswordInput) -> Result<(), ApiError> {
    let change = prepare(state, &attempt, input)?;
    let gate = store::update_lock(&state.directory).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "password_change_busy")
        } else {
            ApiError::internal()
        }
    })?;
    let generation = state.security()?.begin_password_change(&attempt)?;
    let outcome = store::administrators::change_password(&state.directory, &change, &gate);
    complete(state, generation, outcome)
}

/// Finish hashing before entering either writer/fence. Only verified, zeroizing
/// PHCs leave the password worker; plaintext is dropped before witness waits.
fn prepare(
    state: &AppState,
    attempt: &Attempt,
    input: PasswordInput,
) -> Result<store::administrators::PasswordChange, ApiError> {
    let change = store::administrators::prepare_password_change(
        &state.directory,
        &attempt.administrator.id,
        &attempt.administrator.username,
        input.current_password.as_bytes(),
        input.new_password.as_bytes(),
    )
    .map_err(|_| ApiError::internal())?
    .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "invalid_credentials"))?;
    drop(input);
    Ok(change)
}

/// Run as an owned Tokio task, not the cancellable HTTP waiter. Hashing releases
/// its blocking thread before the dedicated source worker needs TLS authority
/// reads. The task retains password capacity and AppState through fence cleanup;
/// dropping the HTTP JoinHandle does not abort it. Unknown source outcomes keep
/// the login fence, even if local SQL already shows the new verifier.
#[cfg(feature = "witness-journal")]
async fn perform_source(
    state: Arc<AppState>,
    attempt: Attempt,
    input: PasswordInput,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), ApiError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let hashing_state = state.clone();
    let (prepared, permit) = tokio::task::spawn_blocking(move || {
        let prepared = prepare(&hashing_state, &attempt, input).map(|change| (change, attempt));
        (prepared, permit)
    })
    .await
    .map_err(|_| ApiError::internal())?;
    let _permit = permit;
    let (change, attempt) = prepared?;
    let generation = attempt
        .generation
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let entered = Arc::new(AtomicBool::new(false));
    let entered_worker = entered.clone();
    let worker_state = state.clone();
    let policy = state.policy.as_ref().ok_or_else(ApiError::internal)?;
    let result = policy
        .source_password_change(change, move || {
            worker_state.security()?.begin_password_change(&attempt)?;
            entered_worker.store(true, Ordering::Release);
            Ok::<_, ApiError>(())
        })
        .await;
    let outcome = match result {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => return Err(error),
        Err(error) if store::journal::is_uncertain(&error) => Ok(PasswordChangeOutcome::Unknown),
        Err(error) => Err(error),
    };
    if entered.load(Ordering::Acquire) {
        return complete(&state, generation, outcome);
    }
    // Admission, source preflight or current session can reject before this
    // attempt owns a fence. Never clear another request's pending generation.
    match outcome {
        Ok(PasswordChangeOutcome::Unknown) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "password_change_outcome_unknown",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "password_change_busy",
        )),
        _ => Err(ApiError::internal()),
    }
}

/// Keep uncertain outcomes fenced. Even a proven rollback only admits fresh
/// logins; it never restores the old sessions already removed before SQL.
fn complete(
    state: &AppState,
    generation: u64,
    outcome: io::Result<PasswordChangeOutcome>,
) -> Result<(), ApiError> {
    if !matches!(outcome, Ok(PasswordChangeOutcome::Unknown)) {
        state.security()?.finish_password_change(generation)?;
    }
    match outcome {
        Ok(PasswordChangeOutcome::Committed) => Ok(()),
        Ok(PasswordChangeOutcome::Conflict) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "password_change_conflict",
        )),
        Ok(PasswordChangeOutcome::Unknown) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "password_change_outcome_unknown",
        )),
        Ok(PasswordChangeOutcome::NotCommitted) | Err(_) => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "password_change_failed",
        )),
    }
}

pub(super) async fn change(
    State(state): State<Arc<AppState>>,
    Extension(PeerIp(address)): Extension<PeerIp>,
    request: Request,
) -> Result<Response, ApiError> {
    let attempt = attempt(&state, request.headers(), address)?;
    if state.schema_version < 12 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_upgrade_required",
        ));
    }
    let input: PasswordInput = json_with_limit(request, MAX_PASSWORD_JSON_BYTES).await?;
    if input.current_password.len() > super::super::MAX_PASSWORD_BYTES
        || input.current_password.chars().any(char::is_control)
        || input.new_password.len() > super::super::MAX_PASSWORD_BYTES
        || input.new_password.chars().count() < super::super::MIN_PASSWORD_CHARACTERS
        || input.new_password.chars().any(char::is_control)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_password_input",
        ));
    }
    let permit = state
        .password_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "authentication_busy"))?;
    #[cfg(feature = "witness-journal")]
    let source = state
        .policy
        .as_ref()
        .is_some_and(|policy| policy.has_source_writer());
    #[cfg(not(feature = "witness-journal"))]
    let source = false;
    if source {
        #[cfg(feature = "witness-journal")]
        tokio::spawn(perform_source(state, attempt, input, permit))
            .await
            .map_err(|_| ApiError::internal())??;
    } else {
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            perform(&state, attempt, input)
        })
        .await
        .map_err(|_| ApiError::internal())??;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-vproxy-session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::api::tests::{call, fixture_session, managed_state, request};
    use http_body_util::BodyExt as _;
    use rusqlite::Connection;

    const NEW_PASSWORD: &str = "replacement passphrase";

    fn request_change(cookie: &str, body: &str) -> Request {
        let mut request = request(Method::POST, "/api/v1/auth/password", body);
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        request
            .headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        request
    }

    fn input(current: &str, new: &str) -> String {
        serde_json::json!({"current_password": current, "new_password": new}).to_string()
    }

    async fn code(response: Response, expected: StatusCode) -> String {
        assert_eq!(response.status(), expected);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["error"]["code"].as_str().unwrap().to_owned()
    }

    fn database(state: &AppState) -> Connection {
        Connection::open(state.directory.join("management.sqlite3")).unwrap()
    }

    fn administrator(state: &AppState) -> String {
        database(state)
            .query_row(
                "SELECT id FROM administrators WHERE username='admin'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Schema twelve lacks offline owner audit; schema eleven also lacks Web
    /// password audit. Reconstruct the actual historical CHECKs before versioning.
    fn legacy_schema(state: &mut Arc<AppState>, version: u32) {
        assert!([11, 12].contains(&version));
        let connection = database(state);
        store::restore_legacy_owner_audit(&connection).unwrap();
        if version == 11 {
            connection.execute_batch(
            "CREATE TABLE administrator_audit_v11 (
             sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
             entry TEXT NOT NULL CHECK(entry='offline'),action TEXT NOT NULL CHECK(action='reset_password'),
             administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
             recorded_at INTEGER NOT NULL CHECK(recorded_at>=0)
             ) STRICT;
             INSERT INTO administrator_audit_v11 SELECT * FROM administrator_audit;
             DROP TABLE administrator_audit;
             ALTER TABLE administrator_audit_v11 RENAME TO administrator_audit;"
        ).unwrap();
        }
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        let actual_version = store::inspect(&state.directory).unwrap().schema_version;
        Arc::get_mut(state).unwrap().schema_version = actual_version;
    }

    #[tokio::test]
    async fn schema_twelve_password_change_remains_supported_without_offline_owner_upgrade() {
        let (_directory, mut state, cookie) = managed_state();
        legacy_schema(&mut state, 12);
        assert_eq!(
            call(
                state.clone(),
                request_change(&cookie, &input("fixture-password", NEW_PASSWORD))
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(store::inspect(&state.directory).unwrap().schema_version, 12);
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                b"fixture-password",
                &state.dummy_phc
            )
            .unwrap()
            .is_none()
        );
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                NEW_PASSWORD.as_bytes(),
                &state.dummy_phc
            )
            .unwrap()
            .is_some()
        );
        let count: i64 = database(&state).query_row("SELECT count(*) FROM administrator_audit WHERE entry='web' AND action='change_password'", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn change_revalidates_password_revokes_all_own_sessions_and_preserves_other_administrators()
     {
        let (_directory, state, cookie) = managed_state();
        let id = administrator(&state);
        let other_id = URL_SAFE_NO_PAD.encode([7u8; 16]);
        database(&state)
            .execute(
                "INSERT INTO administrators VALUES (?1,'other',?2)",
                rusqlite::params![other_id, state.dummy_phc],
            )
            .unwrap();
        {
            let mut security = state.security().unwrap();
            let mut own = fixture_session(Instant::now());
            own.administrator.id = id.clone();
            security
                .insert_session(None, "second-own-session".into(), own)
                .unwrap();
            let mut other_session = fixture_session(Instant::now());
            other_session.administrator.id = other_id;
            security
                .insert_session(None, "other-session".into(), other_session)
                .unwrap();
        }
        let policy_before = store::policy_status(&state.directory).unwrap().revision;
        let wrong = call(
            state.clone(),
            request_change(&cookie, &input("wrong password", NEW_PASSWORD)),
        )
        .await;
        assert_eq!(
            code(wrong, StatusCode::FORBIDDEN).await,
            "invalid_credentials"
        );
        assert_eq!(state.security().unwrap().sessions.len(), 3);
        let response = call(
            state.clone(),
            request_change(&cookie, &input("fixture-password", NEW_PASSWORD)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        {
            let security = state.security().unwrap();
            assert_eq!(security.sessions.len(), 1);
            assert!(security.sessions.contains_key("other-session"));
            assert!(!security.password_change_pending);
            assert_eq!(security.login_generation, 1);
        }
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                b"fixture-password",
                &state.dummy_phc
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            store::authenticate(
                &state.directory,
                "admin",
                NEW_PASSWORD.as_bytes(),
                &state.dummy_phc
            )
            .unwrap()
            .unwrap()
            .id,
            id
        );
        assert_eq!(
            store::policy_status(&state.directory).unwrap().revision,
            policy_before
        );
        let audit: (String, String, String, i64) = database(&state)
            .query_row(
                "SELECT entry,action,administrator_id,sequence FROM administrator_audit",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(audit, ("web".into(), "change_password".into(), id, 1));
        assert_eq!(
            code(
                call(
                    state.clone(),
                    request_change(&cookie, &input(NEW_PASSWORD, "another passphrase"))
                )
                .await,
                StatusCode::FORBIDDEN
            )
            .await,
            "authentication_required"
        );
    }

    #[tokio::test]
    async fn guards_strict_input_and_bounded_work_precede_password_mutation() {
        let (_directory, state, cookie) = managed_state();
        for (name, value, status, expected) in [
            (
                header::ORIGIN,
                "https://attacker.example",
                StatusCode::FORBIDDEN,
                "invalid_origin",
            ),
            (
                header::CONTENT_TYPE,
                "text/plain",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "json_required",
            ),
            (
                header::HeaderName::from_static("x-csrf-token"),
                "wrong",
                StatusCode::FORBIDDEN,
                "invalid_csrf",
            ),
            (
                header::COOKIE,
                "",
                StatusCode::FORBIDDEN,
                "authentication_required",
            ),
        ] {
            let mut req = request_change(&cookie, &input("fixture-password", NEW_PASSWORD));
            req.headers_mut().insert(name, value.parse().unwrap());
            assert_eq!(code(call(state.clone(), req).await, status).await, expected);
        }
        for body in [
            input("fixture-password", "short"),
            input("fixture-password", "control\npassword"),
            input("fixture-password", &"x".repeat(1025)),
        ] {
            assert_eq!(
                code(
                    call(state.clone(), request_change(&cookie, &body)).await,
                    StatusCode::BAD_REQUEST
                )
                .await,
                "invalid_password_input"
            );
        }
        let extra = r#"{"current_password":"fixture-password","new_password":"replacement passphrase","administrator_id":"someone-else"}"#;
        assert_eq!(
            code(
                call(state.clone(), request_change(&cookie, extra)).await,
                StatusCode::BAD_REQUEST
            )
            .await,
            "invalid_json"
        );
        let permits = state
            .password_work
            .clone()
            .try_acquire_many_owned(2)
            .unwrap();
        assert_eq!(
            code(
                call(
                    state.clone(),
                    request_change(&cookie, &input("fixture-password", NEW_PASSWORD))
                )
                .await,
                StatusCode::SERVICE_UNAVAILABLE
            )
            .await,
            "authentication_busy"
        );
        drop(permits);
        assert_eq!(state.security().unwrap().login_generation, 0);
        assert_eq!(
            database(&state)
                .query_row("SELECT count(*) FROM administrator_audit", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        while state
            .security()
            .unwrap()
            .allow_login("127.0.0.1".parse().unwrap(), Instant::now())
        {}
        assert_eq!(
            code(
                call(
                    state.clone(),
                    request_change(&cookie, &input("fixture-password", NEW_PASSWORD))
                )
                .await,
                StatusCode::TOO_MANY_REQUESTS
            )
            .await,
            "login_rate_limited"
        );
    }

    #[tokio::test]
    async fn late_verified_login_cannot_insert_after_a_real_password_change() {
        let (_directory, state, cookie) = managed_state();
        let old_generation = state.security().unwrap().login_generation;
        // Keep a real verifier worker alive across the competing HTTP mutation.
        // The bounded release avoids hanging runtime shutdown if an assertion fails.
        let login_state = state.clone();
        let (verified, ready) = tokio::sync::oneshot::channel();
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let login = tokio::task::spawn_blocking(move || {
            let administrator = store::authenticate(
                &login_state.directory,
                "admin",
                b"fixture-password",
                &login_state.dummy_phc,
            )
            .unwrap()
            .unwrap();
            verified.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut late = fixture_session(Instant::now());
            late.administrator.id = administrator.id;
            login_state.security().unwrap().insert_verified_session(
                old_generation,
                None,
                "late-login".into(),
                late,
            )
        });
        ready.await.unwrap();
        assert_eq!(
            call(
                state.clone(),
                request_change(&cookie, &input("fixture-password", NEW_PASSWORD))
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        release.send(()).unwrap();
        let error = login.await.unwrap().err().unwrap();
        assert_eq!(error.code, "authentication_required");
        assert!(state.security().unwrap().sessions.is_empty());
    }

    #[tokio::test]
    async fn cancelled_http_waiter_keeps_permit_author_and_finishes_fenced_commit() {
        let (_directory, state, cookie) = managed_state();
        let connection = database(&state);
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        let writer_state = state.clone();
        let writer = tokio::spawn(async move {
            call(
                writer_state,
                request_change(&cookie, &input("fixture-password", NEW_PASSWORD)),
            )
            .await
        });
        timeout(Duration::from_secs(2), async {
            while !state.security().unwrap().password_change_pending {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        writer.abort();
        let _ = writer.await;
        assert_eq!(state.password_work.available_permits(), 1);
        assert!(state.security().unwrap().sessions.is_empty());
        assert_eq!(
            store::lock(&state.directory).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            store::update_lock(&state.directory).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let login = call(
            state.clone(),
            request(
                Method::POST,
                "/api/v1/auth/login",
                r#"{"username":"admin","password":"fixture-password"}"#,
            ),
        )
        .await;
        assert_eq!(
            code(login, StatusCode::SERVICE_UNAVAILABLE).await,
            "authentication_busy"
        );
        connection.execute_batch("COMMIT").unwrap();
        timeout(Duration::from_secs(3), async {
            while state.password_work.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!state.security().unwrap().password_change_pending);
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                NEW_PASSWORD.as_bytes(),
                &state.dummy_phc
            )
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn audit_failure_keeps_old_verifier_but_never_resurrects_revoked_sessions() {
        let (_directory, state, cookie) = managed_state();
        database(&state).execute_batch("CREATE TRIGGER failed_audit BEFORE INSERT ON administrator_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        let response = call(
            state.clone(),
            request_change(&cookie, &input("fixture-password", NEW_PASSWORD)),
        )
        .await;
        assert_eq!(
            code(response, StatusCode::INTERNAL_SERVER_ERROR).await,
            "password_change_failed"
        );
        assert!(state.security().unwrap().sessions.is_empty());
        assert!(!state.security().unwrap().password_change_pending);
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                b"fixture-password",
                &state.dummy_phc
            )
            .unwrap()
            .is_some()
        );
        assert!(
            store::authenticate(
                &state.directory,
                "admin",
                NEW_PASSWORD.as_bytes(),
                &state.dummy_phc
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            database(&state)
                .query_row(
                    "SELECT last_sequence FROM administrator_audit_state",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn generation_exhaustion_and_stale_authority_fail_before_session_revocation() {
        let mut security = SecurityState::new(Instant::now());
        let session = fixture_session(Instant::now());
        let administrator = session.administrator.clone();
        security
            .insert_session(None, "token".into(), session)
            .unwrap();
        security.login_generation = u64::MAX;
        let mut attempt = Attempt {
            token: "token".into(),
            csrf: "c".repeat(43),
            administrator,
            generation: u64::MAX,
        };
        assert_eq!(
            security.begin_password_change(&attempt).err().unwrap().code,
            "internal_error"
        );
        assert!(!security.password_change_pending && security.sessions.contains_key("token"));
        attempt.generation = 0;
        assert_eq!(
            security.begin_password_change(&attempt).err().unwrap().code,
            "authentication_required"
        );
        assert!(security.sessions.contains_key("token"));
    }

    #[test]
    fn unconfirmed_commit_retains_login_fence_and_cannot_restore_old_sessions() {
        let (_directory, state, cookie) = managed_state();
        let token = cookie.split_once('=').unwrap().1;
        let administrator = state
            .security()
            .unwrap()
            .session(token, Instant::now())
            .unwrap()
            .administrator
            .clone();
        let attempt = Attempt {
            token: token.into(),
            csrf: "c".repeat(43),
            administrator,
            generation: 0,
        };
        let generation = state
            .security()
            .unwrap()
            .begin_password_change(&attempt)
            .unwrap();
        assert_eq!(
            complete(&state, generation, Ok(PasswordChangeOutcome::Unknown))
                .err()
                .unwrap()
                .code,
            "password_change_outcome_unknown"
        );
        let mut security = state.security().unwrap();
        assert!(security.password_change_pending && security.sessions.is_empty());
        assert!(
            security
                .insert_verified_session(
                    generation,
                    None,
                    "late".into(),
                    fixture_session(Instant::now())
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn pre_upgrade_store_and_a_logged_out_attempt_cannot_enter_the_fence() {
        let (_directory, mut state, cookie) = managed_state();
        legacy_schema(&mut state, 11);
        assert_eq!(
            code(
                call(
                    state.clone(),
                    request_change(&cookie, &input("fixture-password", NEW_PASSWORD))
                )
                .await,
                StatusCode::SERVICE_UNAVAILABLE
            )
            .await,
            "management_upgrade_required"
        );
        assert_eq!(state.security().unwrap().login_generation, 0);
        let token = cookie.split_once('=').unwrap().1;
        let administrator = state
            .security()
            .unwrap()
            .session(token, Instant::now())
            .unwrap()
            .administrator
            .clone();
        let attempt = Attempt {
            token: token.into(),
            csrf: "c".repeat(43),
            administrator,
            generation: 0,
        };
        state.security().unwrap().sessions.clear();
        assert_eq!(
            state
                .security()
                .unwrap()
                .begin_password_change(&attempt)
                .err()
                .unwrap()
                .code,
            "authentication_required"
        );
        assert!(!state.security().unwrap().password_change_pending);
    }

    #[tokio::test]
    async fn full_length_passwords_accept_json_quotes_backslashes_and_unicode_escapes() {
        for unicode_escapes in [false, true] {
            let (_directory, state, cookie) = managed_state();
            let current = if unicode_escapes { "p" } else { "\\" }.repeat(1024);
            let new = if unicode_escapes { "n" } else { "\"" }.repeat(1024);
            let hash = Argon2::default()
                .hash_password(current.as_bytes())
                .unwrap()
                .to_string();
            database(&state)
                .execute("UPDATE administrators SET password_hash=?1", [hash])
                .unwrap();
            let body = if unicode_escapes {
                format!(
                    r#"{{"current_password":"{}","new_password":"{}"}}"#,
                    "\\u0070".repeat(1024),
                    "\\u006e".repeat(1024)
                )
            } else {
                input(&current, &new)
            };
            assert!(body.len() > MAX_JSON_BYTES && body.len() < MAX_PASSWORD_JSON_BYTES);
            assert_eq!(
                call(state.clone(), request_change(&cookie, &body))
                    .await
                    .status(),
                StatusCode::NO_CONTENT
            );
            assert!(
                store::authenticate(&state.directory, "admin", new.as_bytes(), &state.dummy_phc)
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn larger_password_body_limit_stays_bounded_without_widening_other_routes() {
        let (_directory, state, cookie) = managed_state();
        assert_eq!(
            code(
                call(
                    state.clone(),
                    request_change(&cookie, &" ".repeat(MAX_PASSWORD_JSON_BYTES + 1))
                )
                .await,
                StatusCode::PAYLOAD_TOO_LARGE
            )
            .await,
            "body_too_large"
        );
        assert_eq!(state.security().unwrap().login_generation, 0);
        assert!(!state.security().unwrap().sessions.is_empty());
        assert_eq!(
            code(
                call(
                    state,
                    request(
                        Method::POST,
                        "/api/v1/auth/login",
                        &" ".repeat(MAX_JSON_BYTES + 1)
                    )
                )
                .await,
                StatusCode::PAYLOAD_TOO_LARGE
            )
            .await,
            "body_too_large"
        );
    }
}

#[cfg(all(test, feature = "witness-journal"))]
mod source_tests {
    use super::*;
    use crate::manage::api::tests::{call, fixture_session, request};
    use crate::manage::{node, store::journal::SourceFixture};
    use argon2::{Argon2, PasswordHasher as _};
    use http_body_util::BodyExt as _;
    use std::fs;

    const OLD: &str = "source original passphrase";
    const NEW: &str = "source replacement passphrase";

    async fn fixture(
        fault: node::tests::CutResponse,
        fail_audit: bool,
    ) -> io::Result<(SourceFixture, Arc<AppState>, String)> {
        let hash = tokio::task::spawn_blocking(|| {
            Argon2::default()
                .hash_password(OLD.as_bytes())
                .map(|hash| hash.to_string())
                .map_err(io::Error::other)
        })
        .await
        .map_err(io::Error::other)??;
        let stored = hash.clone();
        let live = SourceFixture::new_with(fault, move |f| {
        let c = rusqlite::Connection::open(f.client_state.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        c.execute("UPDATE administrators SET password_hash=?1", [&stored])
            .map_err(io::Error::other)?;
        if fail_audit {
            c.execute_batch("CREATE TRIGGER fail_password_audit BEFORE INSERT ON administrator_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;")
                .map_err(io::Error::other)?;
        }
        Ok(())
    }).await?;
        let mut state = crate::manage::api::tests::state();
        let state_mut =
            Arc::get_mut(&mut state).ok_or_else(|| io::Error::other("shared fixture"))?;
        state_mut.directory = live.fixture.client_state.clone();
        state_mut.schema_version = store::SCHEMA_VERSION;
        state_mut.node.node_id = live.fixture.client_id.clone();
        state_mut.dummy_phc = hash;
        state_mut.policy = Some(live.source.clone());
        state_mut._author = Some(live.author.clone());
        let token = "t".repeat(43);
        let mut session = fixture_session(Instant::now());
        session.administrator.id = live.administrator.clone();
        state
            .security()
            .map_err(|_| io::Error::other("fixture security"))?
            .insert_session(None, token.clone(), session)
            .map_err(|_| io::Error::other("fixture session"))?;
        Ok((live, state, format!("{COOKIE_NAME}={token}")))
    }

    fn change_request(cookie: &str, password: &str) -> Request {
        let body = serde_json::json!({"current_password":password,"new_password":NEW}).to_string();
        let mut r = request(Method::POST, "/api/v1/auth/password", &body);
        r.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        r.headers_mut()
            .insert("x-csrf-token", "c".repeat(43).parse().unwrap());
        r
    }

    fn login_request(password: &str) -> Request {
        request(
            Method::POST,
            "/api/v1/auth/login",
            &serde_json::json!({"username":"admin","password":password}).to_string(),
        )
    }

    async fn error_code(response: Response, status: StatusCode) -> String {
        assert_eq!(response.status(), status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"]["code"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn audit_count(state: &AppState) -> io::Result<i64> {
        let c = rusqlite::Connection::open_with_flags(
            state.directory.join("management.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(io::Error::other)?;
        c.query_row("SELECT count(*) FROM administrator_audit", [], |r| r.get(0))
            .map_err(io::Error::other)
    }

    #[test]
    fn source_password_http_route_completes_with_one_blocking_thread_and_readonly_stale_cas()
    -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()?
            .block_on(async {
                let (live, state, cookie) = fixture(Default::default(), false).await?;
                let result = async {
                    assert_eq!(
                        error_code(
                            call(state.clone(), change_request(&cookie, "wrong")).await,
                            StatusCode::FORBIDDEN
                        )
                        .await,
                        "invalid_credentials"
                    );
                    assert_eq!(state.security().unwrap().sessions.len(), 1);
                    let directory = state.directory.clone();
                    let id = live.administrator.clone();
                    let stale = tokio::task::spawn_blocking(move || {
                        store::administrators::prepare_password_change(
                            &directory,
                            &id,
                            "admin",
                            OLD.as_bytes(),
                            b"stale candidate passphrase",
                        )
                    })
                    .await
                    .map_err(io::Error::other)??
                    .ok_or_else(|| io::Error::other("fixture change"))?;
                    let response = call(state.clone(), change_request(&cookie, OLD)).await;
                    assert_eq!(response.status(), StatusCode::NO_CONTENT);
                    assert!(
                        response.headers()[header::SET_COOKIE]
                            .to_str()
                            .unwrap()
                            .contains("Max-Age=0")
                    );
                    assert!(!state.security().unwrap().password_change_pending);
                    assert!(state.security().unwrap().sessions.is_empty());
                    assert_eq!(state.password_work.available_permits(), 2);
                    assert_eq!(
                        (
                            live.floor()?.sequence,
                            audit_count(&state)?,
                            live.source.reader().revision()?
                        ),
                        ("1".into(), 1, 1)
                    );
                    let conflict = live
                        .source
                        .source_password_change(stale, || Ok::<_, ()>(()))
                        .await?
                        .map_err(|_| io::Error::other("unexpected fence refusal"))?;
                    assert!(matches!(conflict, PasswordChangeOutcome::Conflict));
                    assert_eq!(
                        (live.floor()?.sequence, audit_count(&state)?),
                        ("1".into(), 1)
                    );
                    assert_eq!(
                        call(state.clone(), login_request(OLD)).await.status(),
                        StatusCode::FORBIDDEN
                    );
                    assert_eq!(
                        call(state.clone(), login_request(NEW)).await.status(),
                        StatusCode::OK
                    );
                    Ok(())
                }
                .await;
                drop(state);
                let closed = live.close().await;
                result.and(closed)
            })
    }

    #[tokio::test]
    async fn source_password_internal_sql_failure_keeps_conservative_fence_without_retry()
    -> io::Result<()> {
        let (live, state, cookie) = fixture(Default::default(), true).await?;
        let result = async {
            assert_eq!(
                error_code(
                    call(state.clone(), change_request(&cookie, OLD)).await,
                    StatusCode::SERVICE_UNAVAILABLE
                )
                .await,
                "password_change_outcome_unknown"
            );
            assert!(state.security().unwrap().password_change_pending);
            assert!(state.security().unwrap().sessions.is_empty());
            assert_eq!(state.security().unwrap().login_generation, 1);
            assert_eq!(
                (live.floor()?.sequence, audit_count(&state)?),
                ("0".into(), 0)
            );
            assert!(live.source.reader().revision().is_err());
            assert_eq!(
                fs::read_dir(state.directory.join("witness-intents"))?.count(),
                0
            );
            live.source.reconcile_source().await?;
            assert_eq!(live.source.reader().revision()?, 1);
            assert!(state.security().unwrap().password_change_pending);
            assert_eq!(
                call(state.clone(), login_request(OLD)).await.status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(
                store::authenticate(&state.directory, "admin", OLD.as_bytes(), &state.dummy_phc)?
                    .is_some()
            );
            assert_eq!(audit_count(&state)?, 0);
            Ok(())
        }
        .await;
        drop(state);
        let closed = live.close().await;
        result.and(closed)
    }

    #[tokio::test]
    async fn cancelled_source_password_http_wait_retains_capacity_and_unknown_login_fence()
    -> io::Result<()> {
        for loss in [None, Some(true), Some(false)] {
            let reserve = loss.unwrap_or(false);
            let pause = Arc::new(node::tests::ResponsePause::default());
            let (live, state, cookie) = fixture(
                node::tests::CutResponse {
                    witness_reserve: reserve,
                    witness_confirm: !reserve,
                    pause: Some(pause.clone()),
                    cut_after_pause: loss.is_some(),
                    ..Default::default()
                },
                false,
            )
            .await?;
            let result = async {
                live.arm();
                let state_http = state.clone();
                let waiter =
                    tokio::spawn(
                        async move { call(state_http, change_request(&cookie, OLD)).await },
                    );
                timeout(Duration::from_secs(15), pause.entered.notified())
                    .await
                    .map_err(io::Error::other)?;
                assert!(state.security().unwrap().password_change_pending);
                assert!(state.security().unwrap().sessions.is_empty());
                assert_eq!(state.password_work.available_permits(), 1);
                assert_eq!(
                    error_code(
                        call(state.clone(), login_request(OLD)).await,
                        StatusCode::SERVICE_UNAVAILABLE
                    )
                    .await,
                    "authentication_busy"
                );
                waiter.abort();
                let _ = waiter.await;
                assert_eq!(state.password_work.available_permits(), 1);
                assert!(store::update_lock(&state.directory).is_err());
                pause.release.notify_one();
                timeout(Duration::from_secs(15), async {
                    while state.password_work.available_permits() != 2 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(io::Error::other)?;
                if loss.is_some() {
                    assert!(state.security().unwrap().password_change_pending);
                    assert!(live.source.reader().revision().is_err());
                    // Local SQL alone cannot release the fence after lost replies.
                    assert_eq!(audit_count(&state)?, i64::from(!reserve));
                    live.source.reconcile_source().await?;
                    assert!(state.security().unwrap().password_change_pending);
                    assert_eq!(
                        error_code(
                            call(state.clone(), login_request(NEW)).await,
                            StatusCode::SERVICE_UNAVAILABLE
                        )
                        .await,
                        "authentication_busy"
                    );
                } else {
                    assert!(!state.security().unwrap().password_change_pending);
                    assert_eq!(
                        call(state.clone(), login_request(NEW)).await.status(),
                        StatusCode::OK
                    );
                }
                assert_eq!(
                    (
                        audit_count(&state)?,
                        live.floor()?.sequence,
                        live.source.reader().revision()?
                    ),
                    (1, "1".into(), 1)
                );
                assert!(
                    store::authenticate(
                        &state.directory,
                        "admin",
                        NEW.as_bytes(),
                        &state.dummy_phc
                    )?
                    .is_some()
                );
                let mut security = state.security().unwrap();
                assert!(
                    security
                        .insert_verified_session(
                            0,
                            None,
                            "late".into(),
                            fixture_session(Instant::now())
                        )
                        .is_err()
                );
                Ok(())
            }
            .await;
            pause.release.notify_one();
            drop(state);
            let closed = live.close().await;
            result.and(closed)?;
        }
        Ok(())
    }
}
