use crate::proxy::auth::{Extensions, Whitelist};
use base64::Engine;
use http::{header, HeaderMap};
use std::net::{IpAddr, SocketAddr};

/// Auth Error
#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Missing credentials")]
    MissingCredentials,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unauthorized")]
    Unauthorized,
}

/// Enum representing different types of authenticators.
#[derive(Clone)]
pub enum Authenticator {
    /// No authentication with an IP whitelist.
    None(Vec<IpAddr>),
    /// Password authentication with a username, password, and IP whitelist.
    Password {
        username: String,
        password: String,
        whitelist: Vec<IpAddr>,
    },
}

impl Whitelist for Authenticator {
    fn is_empty(&self) -> bool {
        let whitelist = match self {
            Authenticator::None(whitelist) => whitelist,
            Authenticator::Password { whitelist, .. } => whitelist,
        };

        // Check if the whitelist is empty
        whitelist.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let whitelist = match self {
            Authenticator::None(whitelist) => whitelist,
            Authenticator::Password { whitelist, .. } => whitelist,
        };

        // If whitelist is empty, allow all
        whitelist.contains(&ip)
    }
}

impl Authenticator {
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        socket: SocketAddr,
    ) -> Result<Extensions, AuthError> {
        match self {
            Authenticator::None(..) => {
                // If whitelist is empty, allow all
                let is_equal = self.contains(socket.ip()) || self.is_empty();
                if !is_equal {
                    tracing::warn!("Unauthorized access from {}", socket);
                    return Err(AuthError::Unauthorized);
                }
                Ok(Extensions::None)
            }
            Authenticator::Password {
                username, password, ..
            } => {
                let hv = headers
                    .get(header::PROXY_AUTHORIZATION)
                    .ok_or_else(|| AuthError::MissingCredentials)?;

                // Extract basic auth
                let basic_auth = hv
                    .to_str()
                    .map_err(|_| AuthError::InvalidCredentials)?
                    .strip_prefix("Basic ")
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // Convert to string
                let auth_bytes = base64::engine::general_purpose::STANDARD
                    .decode(basic_auth.as_bytes())
                    .map_err(|_| AuthError::InvalidCredentials)?;
                let auth_str =
                    String::from_utf8(auth_bytes).map_err(|_| AuthError::InvalidCredentials)?;
                let (auth_username, auth_password) = auth_str
                    .split_once(':')
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // Check if the username and password are correct
                let is_equal =
                    ({ auth_username.starts_with(&*username) && auth_password.eq(&*password) })
                        || self.contains(socket.ip());

                // Check credentials
                if is_equal {
                    Ok(Extensions::from((username.as_str(), auth_username)))
                } else {
                    tracing::warn!("Unauthorized access from {}", socket);
                    return Err(AuthError::Unauthorized);
                }
            }
        }
    }
}
