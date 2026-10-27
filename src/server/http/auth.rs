use http::HeaderMap;

use super::Error;
use crate::server::auth::{self, Authenticated, Service, Source, basic_credentials};

/// HTTP credential decoding over the explicit legacy or managed admission source.
#[derive(Clone)]
pub(super) struct Authenticator(pub(super) Source);

impl Authenticator {
    pub(super) async fn authenticate(&self, headers: &HeaderMap) -> Result<Authenticated, Error> {
        let credentials = self
            .0
            .requires_password()
            .then(|| basic_credentials(headers))
            .flatten();
        self.0
            .authenticate(
                credentials.as_ref().map(|value| value.username()),
                credentials
                    .as_ref()
                    .map(|value| value.password().as_bytes()),
                Service::Http,
            )
            .await
            .and_then(|mut authenticated| {
                authenticated.extension = authenticated.tcp_extension()?;
                Ok(authenticated)
            })
            .map_err(|error| match error {
                // Missing, partial and wrong proxy credentials all receive a
                // fresh challenge, unlike a valid identity denied by policy.
                // https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4
                auth::Error::InvalidCredentials => Error::ProxyAuthenticationRequired,
                auth::Error::Unavailable => Error::ServiceUnavailable,
                auth::Error::Denied => Error::Forbidden,
                #[cfg(feature = "management")]
                auth::Error::Capacity => Error::ServiceUnavailable,
            })
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use http::{HeaderValue, header::PROXY_AUTHORIZATION};

    use super::*;

    #[tokio::test]
    async fn authentication_uses_basic_decoding_and_preserves_extensions() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("user-session-client-a:pass:word");
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(&format!("bAsIc   {encoded}")).expect("valid credentials header"),
        );
        let authenticator = Authenticator(Source::Legacy(crate::AuthMode {
            username: Some("user".to_owned()),
            password: Some("pass:word".to_owned()),
        }));
        assert!(matches!(
            authenticator.authenticate(&headers).await,
            Ok(Authenticated {
                extension: crate::ext::Extension::Session(_),
                ..
            })
        ));

        headers.append(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNzOndvcmQ="),
        );
        assert!(matches!(
            authenticator.authenticate(&headers).await,
            Err(Error::ProxyAuthenticationRequired)
        ));
    }

    #[tokio::test]
    async fn invalid_password_requires_a_new_proxy_challenge() {
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjp3cm9uZw=="),
        );
        let authenticator = Authenticator(Source::Legacy(crate::AuthMode {
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
        }));
        assert!(matches!(
            authenticator.authenticate(&headers).await,
            Err(Error::ProxyAuthenticationRequired)
        ));
    }
}
