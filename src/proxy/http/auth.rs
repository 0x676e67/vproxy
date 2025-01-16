use crate::proxy::extension::Extension;
use crate::proxy::http::empty;
use base64::Engine;
use bytes::Bytes;
use http::{header, HeaderMap, Response, StatusCode};
use http_body_util::combinators::BoxBody;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    ProxyAuthenticationRequired,
    #[error("Forbidden")]
    Forbidden,
}

impl TryInto<Response<BoxBody<Bytes, hyper::Error>>> for AuthError {
    type Error = http::Error;
    fn try_into(self) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Self::Error> {
        match self {
            AuthError::ProxyAuthenticationRequired => Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(header::PROXY_AUTHENTICATE, "Basic realm=\"Proxy\"")
                .body(empty()),
            AuthError::Forbidden => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(empty()),
        }
    }
}

/// Enum representing different types of authenticators.
#[derive(Clone)]
pub enum Authenticator {
    /// No authentication with an IP whitelist.
    None,
    /// Password authentication with a username, password, and IP whitelist.
    Password { username: String, password: String },
}

impl Authenticator {
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Extension, AuthError> {
        match self {
            Authenticator::None => Extension::try_from_headers(&headers)
                .await
                .map_err(|_| AuthError::Forbidden),
            Authenticator::Password {
                username, password, ..
            } => {
                // Extract basic auth
                let auth_str =
                    option_ext(&headers).ok_or(AuthError::ProxyAuthenticationRequired)?;
                // Find last ':' index
                let last_colon_index = auth_str
                    .rfind(':')
                    .ok_or(AuthError::ProxyAuthenticationRequired)?;
                let (auth_username, auth_password) = auth_str.split_at(last_colon_index);
                let auth_password = &auth_password[1..];

                // Check if the username and password are correct
                let is_equal =
                    auth_username.starts_with(&*username) && auth_password.eq(&*password);

                // Check credentials
                if is_equal {
                    let extensions = Extension::try_from((username, auth_username))
                        .await
                        .map_err(|_| AuthError::Forbidden)?;
                    Ok(extensions)
                } else {
                    Err(AuthError::Forbidden)
                }
            }
        }
    }
}

fn option_ext(headers: &HeaderMap) -> Option<String> {
    let basic_auth = headers
        .get(header::PROXY_AUTHORIZATION)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.strip_prefix("Basic "))?;

    let auth_bytes = base64::engine::general_purpose::STANDARD
        .decode(basic_auth.as_bytes())
        .ok()?;

    String::from_utf8(auth_bytes).ok()
}
