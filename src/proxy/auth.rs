use super::murmur;
use std::net::IpAddr;

pub trait Whitelist {
    fn contains(&self, ip: IpAddr) -> bool;
}

#[derive(Clone, Copy)]
pub enum Extentions {
    None,
    Session((u64, u64)),
}

impl Default for Extentions {
    fn default() -> Self {
        Extentions::None
    }
}

impl From<(&str, &str)> for Extentions {
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
                    return Extentions::Session((a, b));
                }
            }
        }
        // If the string `s` does not start with the prefix, or if the remaining string
        // after removing the prefix and "-" is empty, return the `None` variant
        // of `AuthExpand`.
        Extentions::None
    }
}
