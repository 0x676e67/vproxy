use std::{
    num::NonZeroU64,
    time::{SystemTime, UNIX_EPOCH},
};

use super::rand;
use crate::ebpf::Profile;

/// Enum representing different types of extensions.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Default)]
pub enum Extension {
    #[default]
    None,
    TTL(u64),
    Range(u64),
    Session(u64),
    /// A leading device selector plus the independent legacy routing decision.
    /// It never reinterprets text embedded inside a session value.
    Profiled {
        route: RouteExtension,
        profile: Profile,
    },
}

/// The routing part of an extension, independent of the SYN preset. Keeping the
/// old Extension variants preserves existing managed admission call sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RouteExtension {
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
        tokio::task::spawn_blocking(move || parse_profiled(prefix, full)).await?
    }

    /// Extracts routing without allowing a device choice to alter address
    /// selection. Both old variants and a profiled route use this same value.
    pub(crate) const fn route(self) -> RouteExtension {
        match self {
            Self::None => RouteExtension::None,
            Self::TTL(value) => RouteExtension::TTL(value),
            Self::Range(value) => RouteExtension::Range(value),
            Self::Session(value) => RouteExtension::Session(value),
            Self::Profiled { route, .. } => route,
        }
    }

    /// An absent selector preserves native behavior; there is no named native
    /// preset that could be confused with an applied packet transformation.
    pub(crate) const fn profile(self) -> Option<Profile> {
        match self {
            Self::Profiled { profile, .. } => Some(profile),
            _ => None,
        }
    }
}

/// Only the exact prefix immediately following the authenticated username can
/// introduce a device. Remove it before invoking the unchanged legacy parser,
/// so session/range hashes are identical to their device-free equivalents.
/// Unknown/empty selectors are input errors without recording the username.
fn parse_profiled(prefix: String, full: String) -> crate::Result<Extension> {
    let Some(suffix) = full.strip_prefix(&prefix) else {
        return Ok(Extension::None);
    };
    let Some(device) = suffix.strip_prefix("-device-") else {
        return Ok(parser(prefix, full));
    };
    let (device, route) = match device.split_once('-') {
        Some((device, route)) => (device, Some(route)),
        None => (device, None),
    };
    let profile = device.parse::<Profile>().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown device profile")
    })?;
    let route = match route {
        Some("") => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty device routing extension",
            )
            .into());
        }
        Some(route) => {
            let (kind, value) = route
                .split_once('-')
                .filter(|(_, value)| !value.is_empty())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "empty device routing extension",
                    )
                })?;
            let full = format!("{prefix}-{route}");
            // A profiled suffix has one route selector; do not reinterpret an
            // unknown or repeated selector as a successful profile-only login.
            let extension = match kind {
                "session" => parse_session_extension(&full),
                "range" => parse_range_extension(value),
                "ttl" => parse_ttl_extension(value),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unknown device routing extension",
                    )
                    .into());
                }
            };
            if matches!(extension, Extension::None) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid device routing extension",
                )
                .into());
            }
            extension.route()
        }
        None => RouteExtension::None,
    };
    Ok(Extension::Profiled { route, profile })
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
#[tracing::instrument(level = "trace", skip_all)]
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
    fn device_selection_preserves_legacy_route_hashes_and_session_text() {
        for (profile, expected) in [
            ("windows", Profile::Windows),
            ("linux", Profile::Linux),
            ("android", Profile::Android),
            ("macos", Profile::MacOs),
            ("ios", Profile::Ios),
        ] {
            let selected = parse_profiled("user".into(), format!("user-device-{profile}"))
                .expect("known device");
            assert_eq!(selected.profile(), Some(expected));
            assert_eq!(selected.route(), RouteExtension::None);
            for route in ["session-client-a-device-ios", "range-client-a"] {
                let native = parser("user".into(), format!("user-{route}"));
                let selected =
                    parse_profiled("user".into(), format!("user-device-{profile}-{route}"))
                        .expect("device and route");
                assert_eq!(selected.route(), native.route());
                assert_eq!(selected.profile(), Some(expected));
            }
        }
        for username in [
            "user-session-client-a-device-windows",
            "user-range-client-a-device-windows",
        ] {
            let selected = parse_profiled("user".into(), username.into()).expect("legacy value");
            assert_eq!(selected.profile(), None);
            assert_eq!(
                selected.route(),
                parser("user".into(), username.into()).route()
            );
        }
    }

    #[test]
    fn malformed_leading_devices_are_not_silently_native() {
        for username in [
            "user-device-",
            "user-device-native",
            "user-device-Windows",
            "user-device-freebsd",
            "user-device-windows-",
            "user-device-windows-device-linux",
            "user-device-windows-session-",
            "user-device-windows-range-",
            "user-device-windows-ttl-0",
        ] {
            let error = parse_profiled("user".into(), username.into()).expect_err("invalid device");
            assert!(matches!(error, crate::error::Error::IO(ref error)
                if error.kind() == std::io::ErrorKind::InvalidInput));
            assert!(!error.to_string().contains(username));
        }
        // This port does not tighten the historical device-free grammar.
        assert!(matches!(
            parse_profiled("user".into(), "user-unknown-value".into())
                .expect("unchanged legacy parser"),
            Extension::None
        ));
    }

    #[test]
    fn ttl_extension_requires_a_nonzero_integer() {
        for input in ["0", "abc"] {
            assert!(matches!(parse_ttl_extension(input), Extension::None));
        }
        assert!(matches!(parse_ttl_extension("60"), Extension::TTL(_)));
    }
}
