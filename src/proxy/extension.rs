use super::{murmur, socks5::proto::UsernamePassword};
use http::HeaderMap;
use std::net::IpAddr;

/// Trait for checking if an IP address is in the whitelist.
pub trait Whitelist {
    /// Checks are empty.
    fn is_empty(&self) -> bool;

    /// Checks if the given IP address is in the whitelist.
    fn contains(&self, ip: IpAddr) -> bool;
}

/// Enum representing different types of extensions.
#[derive(Clone)]
pub enum Extensions {
    /// No extension.
    None,
    /// Session extension with a tuple of two 64-bit integers.
    Session((u64, u64)),
    /// Http to Socks5 extension. e.g. host:port:username:password
    HttpToSocks5(((String, u16), Option<UsernamePassword>)),
}

impl Extensions {
    const HTTP_TO_SOCKS5_HEADER: &'static str = "http-to-socks5";
    const SESSION_ID_HEADER: &'static str = "session-id";

    fn new(s: &str) -> Self {
        // If the remaining string is not empty, it is considered as the session ID.
        if !s.is_empty() {
            let (a, b) = murmur::murmurhash3_x64_128(s.as_bytes(), s.len() as u64);
            Extensions::Session((a, b))
        } else {
            Extensions::None
        }
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Extensions::None
    }
}

impl From<(&str, &str)> for Extensions {
    // This function takes a tuple of two strings as input: a prefix (the username)
    // and a string `s` (the username-session-id).
    fn from((prefix, s): (&str, &str)) -> Self {
        // Check if the string `s` starts with the prefix (username).
        if s.starts_with(prefix) {
            // If it does, remove the prefix from `s`.
            if let Some(s) = s.strip_prefix(prefix) {
                // Then, remove the "-session-" character that follows the prefix.
                if s.starts_with("-session-") {
                    let s = s.trim_start_matches("-session-");
                    // Return it wrapped in the `Session` variant of `Extensions`.
                    return Self::new(s);
                }

                // Then, remove the "-h2s-" character that follows the prefix.
                if s.starts_with("-h2s-") {
                    let s = s.trim_start_matches("-h2s-");
                    // Split host:port:username:password
                    return parse_socks5_extension(s);
                }
            }
        }
        // If the string `s` does not start with the prefix, or if the remaining string
        // after removing the prefix and "-" is empty, return the `None` variant
        // of `Extensions`.
        Extensions::None
    }
}

impl From<&mut HeaderMap> for Extensions {
    fn from(headers: &mut HeaderMap) -> Self {
        // Get the value of the `session-id` header from the headers.
        if let Some(value) = headers.get(Self::SESSION_ID_HEADER) {
            // Convert the value to a string.
            if let Ok(s) = value.to_str() {
                // Return it wrapped in the `Session` variant of `Extensions`.
                let extensions = Self::new(s);
                headers.remove(Self::SESSION_ID_HEADER);
                return extensions;
            }
        }
        // Get the value of the `http-to-socks5` header from the headers.
        if let Some(value) = headers.get(Self::HTTP_TO_SOCKS5_HEADER) {
            // Convert the value to a string.
            if let Ok(s) = value.to_str() {
                // Split host:port:username:password
                let extensions = parse_socks5_extension(s);
                headers.remove(Self::HTTP_TO_SOCKS5_HEADER);
                return extensions;
            }
        }
        // If the `session-id` header is not present, or if the value is not a valid
        // string, return the `None` variant of `Extensions`.
        Extensions::None
    }
}

/// Parses a SOCKS5 extension string.
///
/// This function takes a string `s` and attempts to parse it into a SOCKS5
/// extension. The string should be in the format `host:port` or
/// `host:port:username:password`.
///
/// If the string is in the format `host:port`, this function will return a
/// `Extensions::HttpToSocks5` variant containing a tuple `(host, port)` and
/// `None`.
///
/// If the string is in the format `host:port:username:password`, this function
/// will return a `Extensions::HttpToSocks5` variant containing a tuple `(host,
/// port)` and a `Some(UsernamePassword)`.
///
/// If the string does not match either of these formats, this function will
/// return `Extensions::None`.
///
/// # Arguments
///
/// * `s` - The string to parse.
///
/// # Returns
///
/// This function returns an `Extensions` enum. If the string can be
/// successfully parsed, it will return a `Extensions::HttpToSocks5` variant.
/// Otherwise, it will return `Extensions::None`.
fn parse_socks5_extension(s: &str) -> Extensions {
    let parts: Vec<&str> = s.split(":").collect();
    match parts.len() {
        2 => {
            if let Ok(port) = parts[1].parse::<u16>() {
                let host = parts[0];
                return Extensions::HttpToSocks5(((host.to_string(), port), None));
            }
        }
        4 => {
            if let Ok(port) = parts[1].parse::<u16>() {
                let host = parts[0];
                let username = parts[2];
                let password = parts[3];
                return Extensions::HttpToSocks5((
                    (host.to_string(), port),
                    Some(UsernamePassword::new(
                        username.to_string(),
                        password.to_string(),
                    )),
                ));
            }
        }
        _ => {}
    }

    // do nothing
    Extensions::None
}
