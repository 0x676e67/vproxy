use http::HeaderMap;

use super::Error;
use crate::server::auth::{self, Authenticated, Service, Source, basic_credentials};

/// HTTP credential decoding over the explicit legacy or managed admission source.
#[derive(Clone)]
pub(super) struct Authenticator(pub(super) Source);

impl Authenticator {
    pub(super) async fn authenticate(
        &self,
        headers: &HeaderMap,
        service: Service,
    ) -> Result<Authenticated, Error> {
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
                service,
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
