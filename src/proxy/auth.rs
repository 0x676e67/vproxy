use super::murmur;
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
                if !s.is_empty() {
                    let (a, b) = murmur::murmurhash3_x64_128(s.as_bytes(), s.len() as u64);
                    return Extensions::Session((a, b));
                }
            }
        }
        // If the string `s` does not start with the prefix, or if the remaining string
        // after removing the prefix and "-" is empty, return the `None` variant
        // of `AuthExpand`.
        Extensions::None
    }
}
