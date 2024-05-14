use crate::proxy::auth::{Whitelist, Extentions};
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

#[derive(Clone)]
pub enum Authenticator {
    None(Vec<IpAddr>),
    Password {
        username: String,
        password: String,
        whitelist: Vec<IpAddr>,
    },
}

impl Whitelist for Authenticator {
    fn contains(&self, ip: IpAddr) -> bool {
        let whitelist = match self {
            Authenticator::None(whitelist) => whitelist,
            Authenticator::Password { whitelist, .. } => whitelist,
        };

        // If whitelist is empty, allow all
        if whitelist.is_empty() {
            return true;
        } else {
            // Check if the ip is in the whitelist
            return whitelist.contains(&ip);
        }
    }
}

impl Authenticator {
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        socket: SocketAddr,
    ) -> Result<Extentions, AuthError> {
        match self {
            Authenticator::None(..) => {
                // If whitelist is empty, allow all
                if !self.contains(socket.ip()) {
                    tracing::warn!("Unauthorized access from {}", socket);
                    return Err(AuthError::Unauthorized);
                }
                Ok(Extentions::None)
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
                    Ok(Extentions::from((username.as_str(), auth_username)))
                } else {
                    tracing::warn!("Unauthorized access from {}", socket);
                    return Err(AuthError::Unauthorized);
                }
            }
        }
    }
}
