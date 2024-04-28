use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use http::{header, HeaderMap};
use tokio::sync::OnceCell;

use super::error::AuthError;
use crate::BootArgs;

/// Basic auth realm
static BASIC_AUTH_REALM: OnceCell<Option<(String, String)>> = OnceCell::const_new();

/// Ip address whitelist
static IP_WHITELIST: OnceCell<Option<Vec<IpAddr>>> = OnceCell::const_new();

/// Init basic auth realm
pub fn init_basic_auth_realm(args: &BootArgs) {
    // Set basic auth realm
    if let (Some(u), Some(p)) = (&args.auth_user, &args.auth_pass) {
        BASIC_AUTH_REALM
            .set(Some((u.to_owned(), p.to_owned())))
            .expect("BASIC_AUTH_REALM should be set only once")
    }
}

/// Init ip whitelist
pub fn init_ip_whitelist(args: &BootArgs) {
    // Set ip whitelist
    if !args.whitelist.is_empty() {
        IP_WHITELIST
            .set(Some(args.whitelist.clone()))
            .expect("IP_WHITELIST should be set only once")
    }
}

/// Valid Ip address whitelist
pub fn valid_ip_whitelist(socket: SocketAddr) -> Result<(), AuthError> {
    if let Some(Some(ip)) = IP_WHITELIST.get() {
        if ip.contains(&socket.ip()) {
            return Ok(());
        }
    }
    Err(AuthError::Unauthorized)
}

/// Valid basic auth
pub fn valid_basic_auth(headers: &HeaderMap) -> Result<(), AuthError> {
    if let Some(Some((auth_username, auth_password))) = BASIC_AUTH_REALM.get() {
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
        let auth_str = String::from_utf8(auth_bytes).map_err(|_| AuthError::InvalidCredentials)?;
        let (username, password) = auth_str
            .split_once(':')
            .ok_or_else(|| AuthError::InvalidCredentials)?;

        // check credentials
        if username.ne(auth_username) || password.ne(auth_password) {
            return Err(AuthError::Unauthorized);
        }
    }
    Ok(())
}
