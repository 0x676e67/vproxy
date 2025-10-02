use base64::Engine;
use http::{HeaderMap, header};

use super::{Error, Extension};

/// Enum representing different types of authenticators.
#[derive(Clone)]
pub enum Authenticator {
    /// No authentication with an IP whitelist.
    None,
    /// Password authentication with a username, password, and IP whitelist.
    Password { username: String, password: String },
}

impl Authenticator {
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Extension, Error> {
        match self {
            Authenticator::None => Ok(Extension::default()),
            Authenticator::Password {
                username, password, ..
            } => {
                let parse_basic_auth = |headers: &HeaderMap| -> Option<String> {
                    let basic_auth = headers
                        .get(header::PROXY_AUTHORIZATION)
                        .and_then(|hv| hv.to_str().ok())
                        .and_then(|s| s.strip_prefix("Basic "))?;

                    let auth_bytes = base64::engine::general_purpose::STANDARD
                        .decode(basic_auth.as_bytes())
                        .ok()?;

                    String::from_utf8(auth_bytes).ok()
                };

                // Parse username and password from headers
                let auth_str =
                    parse_basic_auth(headers).ok_or(Error::ProxyAuthenticationRequired)?;
                // Find last ':' index
                let last_colon_index = auth_str
                    .rfind(':')
                    .ok_or(Error::ProxyAuthenticationRequired)?;
                let (auth_username, auth_password) = auth_str.split_at(last_colon_index);
                let auth_password = &auth_password[1..];

                // Check if the username and password are correct
                let is_equal = auth_username.starts_with(username) && auth_password.eq(password);

                // Check credentials
                if is_equal {
                    let extensions = Extension::try_from(username, auth_username)
                        .await
                        .map_err(|_| Error::Forbidden)?;
                    Ok(extensions)
                } else {
                    Err(Error::Forbidden)
                }
            }
        }
    }
}
