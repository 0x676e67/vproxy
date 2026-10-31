use base64::Engine;
use http::{HeaderMap, header::PROXY_AUTHORIZATION};

use crate::{AuthMode, ext::Extension};

/// Explicit source selection; managed failures must never fall back to legacy
/// credentials or anonymous access.
#[derive(Clone)]
pub(crate) enum Source {
    Legacy(AuthMode),
    #[cfg(feature = "management")]
    Managed(crate::access::Reader),
}

impl From<AuthMode> for Source {
    fn from(mode: AuthMode) -> Self {
        Self::Legacy(mode)
    }
}

/// Actual client-to-proxy service. HTTP and HTTPS share one access permission,
/// but retain separate accounting identities; CONNECT targets do not select it.
#[derive(Clone, Copy)]
pub(crate) enum Service {
    Http,
    Https,
    #[cfg(feature = "management")]
    Socks5,
    Masque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidCredentials,
    Unavailable,
    Denied,
    #[cfg(feature = "management")]
    Capacity,
}

/// One authenticated flow. Only managed admission has a user concurrency lease;
/// legacy requests preserve their existing routing-extension behavior.
pub(crate) struct Authenticated {
    pub(crate) extension: Extension,
    /// A node-local IP selected from the managed user's authorized resources.
    /// Legacy admissions remain `None`; protocol handlers must not fall back
    /// when this exact source cannot bind or reach the target.
    pub(crate) source: Option<std::net::IpAddr>,
    #[cfg(feature = "management")]
    pub(crate) lease: Option<std::sync::Arc<crate::access::FlowLease>>,
    /// Copied TCP choices from this admission, never a live policy lookup. A
    /// SOCKS default remains unresolved until its command is known.
    #[cfg(feature = "management")]
    pub(crate) presets: Option<crate::access::presets::Selection>,
}

impl Authenticated {
    /// Select the permitted active-TCP preset without changing source routing.
    /// A denied pool/user default is an error, not a request for native sockets.
    pub(crate) fn tcp_extension(&self) -> Result<Extension, Error> {
        #[cfg(feature = "management")]
        if let Some(selection) = self.presets {
            return match selection.tcp().map_err(|_| Error::Denied)? {
                Some(profile) => Ok(Extension::Profiled {
                    route: self.extension.route(),
                    profile,
                }),
                None => Ok(self.extension),
            };
        }
        Ok(self.extension)
    }

    /// Defaults do not apply to UDP or passive BIND. An explicit device,
    /// however, cannot be silently ignored for either operation.
    pub(crate) fn explicit_preset(&self) -> bool {
        #[cfg(feature = "management")]
        if self.presets.is_some_and(|selection| selection.explicit()) {
            return true;
        }
        self.extension.profile().is_some()
    }

    /// A direction-bound handle for this admission only. Legacy and anonymous
    /// flows have no managed accounting identity and must not be attributed to
    /// whichever user happened to use the same connection previously.
    #[cfg(feature = "management")]
    pub(crate) fn meter(
        &self,
        direction: crate::traffic::Direction,
    ) -> Option<crate::traffic::Meter> {
        self.lease.as_ref().map(|lease| lease.meter(direction))
    }

    pub(crate) fn legacy(extension: Extension) -> Self {
        Self {
            extension,
            source: None,
            #[cfg(feature = "management")]
            lease: None,
            #[cfg(feature = "management")]
            presets: None,
        }
    }
}

impl Source {
    pub(crate) fn requires_password(&self) -> bool {
        match self {
            Self::Legacy(mode) => mode.username.is_some() && mode.password.is_some(),
            #[cfg(feature = "management")]
            Self::Managed(_) => true,
        }
    }

    /// Authenticate decoded credentials; no headers or passwords enter logs.
    /// Managed verification is synchronous bounded memory work. Only the legacy
    /// parser retains its historical blocking dispatch and prefix semantics.
    pub(crate) async fn authenticate(
        &self,
        username: Option<&str>,
        password: Option<&[u8]>,
        _service: Service,
    ) -> Result<Authenticated, Error> {
        let authenticated = match self {
            Self::Legacy(mode) => {
                let (Some(expected), Some(secret)) = (&mode.username, &mode.password) else {
                    return Ok(Authenticated::legacy(Extension::None));
                };
                let username = username.ok_or(Error::InvalidCredentials)?;
                if !username.starts_with(expected) || password != Some(secret.as_bytes()) {
                    return Err(Error::InvalidCredentials);
                }
                let extension = Extension::try_from(expected, username)
                    .await
                    .map_err(|error| match error {
                        // Rejected selector syntax is a credential input
                        // failure, not an unavailable proxy or backend.
                        crate::error::Error::IO(error)
                            if error.kind() == std::io::ErrorKind::InvalidInput =>
                        {
                            Error::InvalidCredentials
                        }
                        _ => Error::Unavailable,
                    })?;
                Ok(Authenticated::legacy(extension))
            }
            #[cfg(feature = "management")]
            Self::Managed(reader) => {
                let protocol = match _service {
                    Service::Http | Service::Https => crate::access::Protocol::Http,
                    Service::Socks5 => crate::access::Protocol::Socks5,
                    Service::Masque => crate::access::Protocol::Masque,
                };
                let username = username.ok_or(Error::InvalidCredentials)?;
                let password = password.ok_or(Error::InvalidCredentials)?;
                let result = if matches!(_service, Service::Https) {
                    reader.authenticate_http(username, password, true)
                } else {
                    reader.authenticate(username, password, protocol)
                }
                .map_err(|error| match error {
                    crate::access::Error::InvalidCredentials => Error::InvalidCredentials,
                    crate::access::Error::Denied => Error::Denied,
                    crate::access::Error::Unavailable => Error::Unavailable,
                    crate::access::Error::Capacity => Error::Capacity,
                })?;
                // Stable non-secret IDs let an operator correlate a flow with
                // its policy; wire login, extensions and secret stay absent.
                tracing::trace!(
                    user_id = result.lease.user_id.as_ref(),
                    credential_id = result.lease.credential_id.as_ref(),
                    "managed proxy flow admitted"
                );
                Ok(Authenticated {
                    extension: result.extension,
                    source: result.source,
                    lease: Some(result.lease),
                    presets: Some(result.presets),
                })
            }
        }?;
        // CONNECT-UDP forwards UDP, not a newly originated TCP connection.
        // A device request cannot be fulfilled by its underlying QUIC socket.
        if matches!(_service, Service::Masque) && authenticated.explicit_preset() {
            return Err(Error::Denied);
        }
        Ok(authenticated)
    }
}

/// Decoded Basic credentials shared by HTTP and MASQUE authentication.
///
/// `colon` is the first ASCII colon in the UTF-8 value, so both accessors borrow
/// valid string slices without allocating a second copy of the password. This
/// type intentionally does not implement `Debug` to avoid logging credentials.
pub(super) struct BasicCredentials {
    value: String,
    colon: usize,
}

impl BasicCredentials {
    pub(super) fn username(&self) -> &str {
        &self.value[..self.colon]
    }

    pub(super) fn password(&self) -> &str {
        &self.value[self.colon + 1..]
    }
}

/// Decode one Proxy-Authorization Basic credential, preserving UTF-8 support.
///
/// [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1)
/// makes the scheme case-insensitive; the one-or-more-SP separator follows
/// [§11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4).
/// [RFC 7617 §2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2) requires the
/// first colon to separate the username and password and forbids ASCII CTL in
/// either. Missing, repeated, combined, or malformed credentials return `None`;
/// this function does not decide how either proxy protocol challenges a client.
pub(super) fn basic_credentials(headers: &HeaderMap) -> Option<BasicCredentials> {
    let authorization = headers.get_all(PROXY_AUTHORIZATION);
    let mut values = authorization.iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }

    let (scheme, encoded) = value.to_str().ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim_start_matches(' '))
        .ok()?;
    let value = String::from_utf8(bytes).ok()?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let colon = value.find(':')?;
    Some(BasicCredentials { value, colon })
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[tokio::test]
    async fn malformed_device_selector_is_invalid_credentials_not_backend_unavailability() {
        let source = Source::Legacy(AuthMode {
            username: Some("user".into()),
            password: Some("password".into()),
        });
        for username in [
            "user-device-",
            "user-device-unknown",
            "user-device-ios-ttl-0",
        ] {
            assert!(matches!(
                source
                    .authenticate(Some(username), Some(b"password"), Service::Http)
                    .await,
                Err(Error::InvalidCredentials)
            ));
        }
        // The same text inside a legacy session stays session data.
        assert!(matches!(
            source
                .authenticate(
                    Some("user-session-name-device-ios"),
                    Some(b"password"),
                    Service::Http
                )
                .await,
            Ok(Authenticated {
                extension: Extension::Session(_),
                ..
            })
        ));
        assert!(matches!(
            source
                .authenticate(
                    Some("user-device-linux"),
                    Some(b"password"),
                    Service::Masque
                )
                .await,
            Err(Error::Denied)
        ));
    }

    fn authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(value).expect("valid header value"),
        );
        headers
    }

    #[test]
    fn basic_credentials_preserve_colons_in_password_and_utf8() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("用户:p:a:ss密码");
        let headers = authorization(&format!("Basic {encoded}"));
        let credentials = basic_credentials(&headers).expect("valid credentials");
        assert_eq!(credentials.username(), "用户");
        assert_eq!(credentials.password(), "p:a:ss密码");
    }

    #[test]
    fn basic_credentials_accept_case_insensitive_scheme_and_spaces() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:password");
        for scheme in ["Basic ", "basic ", "bAsIc   "] {
            let headers = authorization(&format!("{scheme}{encoded}"));
            let credentials = basic_credentials(&headers).expect("valid credentials");
            assert_eq!(credentials.username(), "user");
            assert_eq!(credentials.password(), "password");
        }
    }

    #[test]
    fn basic_credentials_reject_malformed_or_repeated_headers() {
        assert!(basic_credentials(&HeaderMap::new()).is_none());
        for value in [
            "Basic",
            "Basic ",
            "Basic\tdXNlcjpwYXNzd29yZA==",
            "Bearer dXNlcjpwYXNzd29yZA==",
            "Basic !!!",
            "Basic dXNlcg==",
            "Basic dXNlcjpwYXNzd29yZA==, Basic dXNlcjpwYXNzd29yZA==",
        ] {
            assert!(basic_credentials(&authorization(value)).is_none());
        }

        let mut headers = authorization("Basic dXNlcjpwYXNzd29yZA==");
        headers.append(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNzd29yZA=="),
        );
        assert!(basic_credentials(&headers).is_none());
    }

    #[test]
    fn basic_credentials_reject_ascii_controls_and_invalid_utf8() {
        for control in (0..=0x1f).chain([0x7f]) {
            for index in [0, 5] {
                let mut value = b"user:password".to_vec();
                value[index] = control;
                let encoded = base64::engine::general_purpose::STANDARD.encode(value);
                assert!(basic_credentials(&authorization(&format!("Basic {encoded}"))).is_none());
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"user:\xff");
        assert!(basic_credentials(&authorization(&format!("Basic {encoded}"))).is_none());
    }
}
