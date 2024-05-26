use super::murmur;
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
#[derive(Clone, Copy)]
pub enum Extensions {
    /// No extension.
    None,
    /// Session extension with a tuple of two 64-bit integers.
    Session((u64, u64)),
}

impl Extensions {
    const SESSION_ID_HEADER: &'static str = "session-id";

    fn new(s: &str) -> Self {
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
                let s = s.trim_start_matches("-session-");
                // If the remaining string is not empty, it is considered as the session ID.
                // Return it wrapped in the `Session` variant of `AuthExpand`.
                return Self::new(s);
            }
        }
        // If the string `s` does not start with the prefix, or if the remaining string
        // after removing the prefix and "-" is empty, return the `None` variant
        // of `AuthExpand`.
        Extensions::None
    }
}

impl From<&mut HeaderMap> for Extensions {
    fn from(headers: &mut HeaderMap) -> Self {
        // Get the value of the `x-session-id` header from the headers.
        if let Some(value) = headers.get(Self::SESSION_ID_HEADER) {
            // Convert the value to a string.
            if let Ok(s) = value.to_str() {
                // If the remaining string is not empty, it is considered as the session ID.
                // Return it wrapped in the `Session` variant of `AuthExpand`.
                let extensions = Self::new(s);
                headers.remove(Self::SESSION_ID_HEADER);
                return extensions;
            }
        }
        // If the `x-session-id` header is not present, or if the value is not a valid
        // string, return the `None` variant of `AuthExpand`.
        Extensions::None
    }
}
