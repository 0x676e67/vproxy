use crate::proxy::auth::AuthError;
use base64::Engine;
use http::{header, HeaderMap};

#[derive(Clone)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    pub fn auth_basic_auth_realm(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        match self {
            AuthenticationMethod::None => Ok(()),
            AuthenticationMethod::Password { username, password } => {
                let hv = headers
                    .get(header::PROXY_AUTHORIZATION)
                    .ok_or_else(|| AuthError::MissingCredentials)?;

                // extract basic auth
                let basic_auth = hv
                    .to_str()
                    .map_err(|_| AuthError::InvalidCredentials)?
                    .strip_prefix("Basic ")
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // convert to string
                let auth_bytes = base64::engine::general_purpose::STANDARD
                    .decode(basic_auth.as_bytes())
                    .map_err(|_| AuthError::InvalidCredentials)?;
                let auth_str =
                    String::from_utf8(auth_bytes).map_err(|_| AuthError::InvalidCredentials)?;
                let (auth_username, auth_password) = auth_str
                    .split_once(':')
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // check credentials
                if username.ne(auth_username) || password.ne(auth_password) {
                    return Err(AuthError::Unauthorized);
                }

                Ok(())
            }
        }
    }
}
