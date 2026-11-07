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
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        perform(&state, attempt, input)
    })
    .await
    .map_err(|_| ApiError::internal())??;
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
        {
            let security = state.security().unwrap();
            assert_eq!(security.sessions.len(), 1);
            assert!(security.sessions.contains_key("other-session"));
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
}
