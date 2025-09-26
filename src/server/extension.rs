use std::{
    num::NonZeroU64,
    time::{SystemTime, UNIX_EPOCH},
};

use super::rand;

/// Enum representing different types of extensions.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Default)]
pub enum Extension {
    #[default]
    None,
    TTL(u64),
    Range(u64),
    Session(u64),
}

impl Extension {
    const EXTENSION_TTL: &'static str = "-ttl-";
    const EXTENSION_SESSION: &'static str = "-session-";
    const EXTENSION_RANGE_SESSION: &'static str = "-range-";

    #[inline]
    pub async fn try_from<O>(prefix: &str, full: O) -> crate::Result<Extension>
    where
        O: Into<String>,
    {
        let full = full.into();
        let prefix = prefix.to_owned();
        tokio::task::spawn_blocking(move || parser(prefix, full))
            .await
            .map_err(Into::into)
    }
}

/// This function takes a tuple of two strings as input: a prefix (the username)
/// and a string `full` (the username-session-id).
#[inline]
fn parser(prefix: String, full: String) -> Extension {
    // If it does, remove the prefix from `s`.
    if let Some(extracted_tag) = full.strip_prefix(&prefix) {
        if let Some(extension) = parse_extension(
            false,
            &full,
            Extension::EXTENSION_SESSION,
            parse_session_extension,
        ) {
            return extension;
        }

        if let Some(extension) = parse_extension(
            true,
            extracted_tag,
            Extension::EXTENSION_TTL,
            parse_ttl_extension,
        ) {
            return extension;
        }

        if let Some(extension) = parse_extension(
            true,
            extracted_tag,
            Extension::EXTENSION_RANGE_SESSION,
            parse_range_extension,
        ) {
            return extension;
        }
    }

    // If the string `s` does not start with the prefix, or if the remaining string
    // after removing the prefix and "-" is empty, return the `None` variant
    // of `Extensions`.
    Extension::None
}

/// Handles an extension string.
///
/// This function takes a string `s`, a prefix, and a handler function.
/// If the string `s` starts with the given prefix, the function removes the
/// prefix and applies the handler function to the remaining string.
///
/// The handler function should take a string and return an `Extensions` enum.
///
/// If the string `s` does not start with the prefix, the function returns
/// `None`.
#[tracing::instrument(level = "trace", skip(handler))]
#[inline]
fn parse_extension(
    trim: bool,
    s: &str,
    prefix: &str,
    handler: fn(&str) -> Extension,
) -> Option<Extension> {
    if !s.contains(prefix) {
        return None;
    }
    let s = if trim {
        s.trim_start_matches(prefix)
    } else {
        s
    };
    let extension = handler(s);
    tracing::trace!("Extension: {:?}", extension);
    Some(extension)
}

/// Parses a Range extension string.
/// This function takes a string `s` and attempts to parse it into a Range
/// extension. The function uses the `murmurhash3_x64_128` function to generate
/// a 128-bit hash from the string. The hash is then returned as a tuple `(a, b)`
/// wrapped in the `Extensions::Range` variant.
#[inline(always)]
fn parse_range_extension(s: &str) -> Extension {
    let hash = fxhash::hash64(s.as_bytes());
    Extension::Range(hash)
}

/// Parses a session extension string.
///
/// This function takes a string `s` and attempts to parse it into a session
/// extension. If the string is not empty, it is considered as the session ID.
///
/// The function uses the `murmurhash3_x64_128` function to generate a 128-bit
/// hash from the session ID. The hash is then returned as a tuple `(a, b)`
/// wrapped in the `Extensions::Session` variant.
///
/// If the string is empty, the function returns `Extensions::None`.
#[inline(always)]
fn parse_session_extension(s: &str) -> Extension {
    let hash = fxhash::hash64(s.as_bytes());
    Extension::Session(hash)
}

/// Parses a TTL (Time To Live) extension string.
///
/// This function attempts to parse a given string `s` into a `u64` representing
/// the TTL value. If successful, it returns an `Extensions::Session` variant
/// with the parsed TTL value and a fixed value of `1`. If the string cannot be
/// parsed into a `u64`, it returns `Extensions::None`.
#[inline]
fn parse_ttl_extension(s: &str) -> Extension {
    if let Ok(Some(ttl)) = s.parse::<u64>().map(NonZeroU64::new) {
        let start = SystemTime::now();
        let timestamp = start
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(rand::random_u64());

        let time = timestamp - (timestamp % ttl.get());
        let hash = fxhash::hash64(&time.to_be_bytes());
        return Extension::TTL(hash);
    }
    Extension::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl_extension_zero() {
        // Should return Extension::None for zero input
        assert!(matches!(parse_ttl_extension("0"), Extension::None));
    }

    #[test]
    fn test_parse_ttl_extension_nonzero() {
        // Should return Extension::TTL for non-zero input
        let ext = parse_ttl_extension("60");
        match ext {
            Extension::TTL(_) => {}
            _ => panic!("Expected Extension::TTL"),
        }
    }

    #[test]
    fn test_parse_ttl_extension_invalid() {
        // Should return Extension::None for invalid input
        assert!(matches!(parse_ttl_extension("abc"), Extension::None));
    }
}
