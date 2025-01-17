use http::{header, HeaderMap};
use tokio::task::JoinError;

/// Enum representing different types of extensions.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Default)]
pub enum Extension {
    /// No extension.
    #[default]
    None,
    /// TTL extension with a 64-bit integer.
    TTL(u64),
    /// Range extension with a 64-bit integers.
    Range(u64),
    /// Session extension with a 64-bit integers.
    Session(u64),
}

impl Extension {
    const TAG_TTL: &'static str = "-ttl-";
    const TAG_SESSION: &'static str = "-session-";
    const TAG_RANGE_SESSION: &'static str = "-range-";

    const HEADER_TTL: &'static str = "ttl";
    const HEADER_RANGE: &'static str = "range";
    const HEADER_SESSION_ID: &'static str = "session";

    pub async fn try_from_headers(headers: &HeaderMap) -> Result<Extension, JoinError> {
        let headers = headers.clone();
        let extension = tokio::task::spawn_blocking(move || Extension::from(&headers)).await?;
        Ok(extension)
    }

    pub async fn try_from((prefix, full): (&str, &str)) -> Result<Extension, JoinError> {
        let prefix = prefix.to_owned();
        let full = full.to_owned();
        let extension =
            tokio::task::spawn_blocking(move || Extension::from((prefix.as_str(), full.as_str())))
                .await?;
        Ok(extension)
    }
}

impl From<(&str, &str)> for Extension {
    // This function takes a tuple of two strings as input: a prefix (the username)
    // and a string `full` (the username-session-id).
    fn from((prefix, full): (&str, &str)) -> Self {
        // If it does, remove the prefix from `s`.
        if let Some(tag) = full.strip_prefix(prefix) {
            // Parse range extension
            if let Some(extension) =
                handle_extension(true, tag, Self::TAG_RANGE_SESSION, parse_range_extension)
            {
                return extension;
            }

            // Parse session extension
            if let Some(extension) =
                handle_extension(false, full, Self::TAG_SESSION, parse_session_extension)
            {
                return extension;
            }

            // Parse ttl extension
            if let Some(extension) = handle_extension(true, tag, Self::TAG_TTL, parse_ttl_extension)
            {
                return extension;
            }
        }
        // If the string `s` does not start with the prefix, or if the remaining string
        // after removing the prefix and "-" is empty, return the `None` variant
        // of `Extensions`.
        Extension::None
    }
}

impl From<&HeaderMap> for Extension {
    fn from(headers: &HeaderMap) -> Self {
        // Get the value of the `range=id` header from the headers.
        if let (Some(value), ident) = (
            headers.get(Self::HEADER_RANGE),
            headers.get(header::PROXY_AUTHORIZATION),
        ) {
            // Convert the value to a string.
            let ident = ident.and_then(|v| v.to_str().ok());
            // Return it wrapped in the `Session` variant of `Extensions`.
            match (value.to_str(), ident) {
                (Ok(s), Some(ident)) => {
                    let extensions = parse_range_extension(format!("{s}{ident}").as_str());
                    return extensions;
                }
                (Ok(s), None) => {
                    let extensions = parse_range_extension(s);
                    return extensions;
                }
                _ => {}
            }
        }

        // Get the value of the `session=id` header from the headers.
        if let (Some(value), ident) = (
            headers.get(Self::HEADER_SESSION_ID),
            headers.get(header::PROXY_AUTHORIZATION),
        ) {
            // Convert the value to a string.
            let ident = ident.and_then(|v| v.to_str().ok());
            // Return it wrapped in the `Session` variant of `Extensions`.
            match (value.to_str(), ident) {
                (Ok(s), Some(ident)) => {
                    let extensions = parse_session_extension(format!("{s}{ident}").as_str());
                    return extensions;
                }
                (Ok(s), None) => {
                    let extensions = parse_session_extension(s);
                    return extensions;
                }
                _ => {}
            }
        }

        // Get the value of the `ttl` header from the headers.
        if let Some(value) = headers.get(Self::HEADER_TTL) {
            // Convert the value to a string.
            if let Ok(s) = value.to_str() {
                // Parse TTL extension
                let extensions = parse_ttl_extension(s);
                return extensions;
            }
        }

        // If the `session-id` header is not present, or if the value is not a valid
        // string, return the `None` variant of `Extensions`.
        Extension::None
    }
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
///
/// # Arguments
///
/// * `trim` - Whether to trim the string before checking the prefix.
/// * `s` - The string to handle.
/// * `prefix` - The prefix to check and remove from the string.
/// * `handler` - The function to apply to the string after removing the prefix.
///
/// # Returns
///
/// This function returns an `Option<Extensions>`. If the string starts with the
/// prefix, it returns `Some(Extensions)`. Otherwise, it returns `None`.
fn handle_extension(
    trim: bool,
    s: &str,
    prefix: &str,
    handler: fn(&str) -> Extension,
) -> Option<Extension> {
    tracing::debug!("before handle_extension: s={}, prefix={}", s, prefix);
    if !s.contains(prefix) {
        return None;
    }
    let s = trim.then(|| s.trim_start_matches(prefix)).unwrap_or(s);
    tracing::debug!("after handle_extension: s={}", s);
    Some(handler(s))
}

/// Parses a Range extension string.
/// This function takes a string `s` and attempts to parse it into a Range
/// extension. The function uses the `murmurhash3_x64_128` function to generate
/// a 128-bit hash from the string. The hash is then returned as a tuple `(a, b)`
/// wrapped in the `Extensions::Range` variant.
/// # Arguments
/// * `s` - The string to parse.
/// # Returns
/// This function returns an `Extensions` enum.
/// If the string is empty, it returns `Extensions::None`.
/// If the string is not empty, it returns `Extensions::Range(a, b)`.
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
///
/// # Arguments
///
/// * `s` - The string to parse.
///
/// # Returns
///
/// This function returns an `Extensions` enum. If the string is not empty, it
/// will return a `Extensions::Session` variant containing a tuple `(a, b)`.
/// Otherwise, it will return `Extensions::None`.
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
///
/// # Arguments
///
/// * `s` - The string to parse as a TTL value.
///
/// # Returns
///
/// Returns an `Extensions` enum variant. If parsing is successful, returns
/// `Extensions::Session` with the TTL value and `1`. Otherwise, returns
/// `Extensions::None`.
fn parse_ttl_extension(s: &str) -> Extension {
    if let Ok(ttl) = s.parse::<u64>() {
        return Extension::TTL(ttl);
    }
    Extension::None
}
