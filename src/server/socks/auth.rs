use std::{future::Future, io::Error};

use crate::{
    ext::Extension,
    server::socks::proto::{Method, UsernamePassword},
};

/// Trait for SOCKS authentication methods.
pub trait Auth: Send {
    type Output;

    /// Returns the SOCKS authentication method type.
    fn method(&self) -> Method;

    /// Validates credentials already decoded from the client.
    fn authenticate(
        &self,
        credentials: Option<UsernamePassword>,
    ) -> impl Future<Output = Self::Output> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("{0}")]
    Rejected(&'static str),

    #[error(transparent)]
    Internal(#[from] Error),
}

impl AuthError {
    #[inline]
    pub(super) fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::Rejected(message) => {
                Error::new(std::io::ErrorKind::PermissionDenied, message)
            }
            AuthError::Internal(error) => error,
        }
    }
}

/// Unified interface for different SOCKS authentication methods.
#[non_exhaustive]
pub enum AuthAdaptor {
    NoAuth(NoAuth),
    Password(Password),
}

impl AuthAdaptor {
    // Create a new [`AuthAdaptor`] instance with no authentication.
    #[inline]
    pub fn no() -> Self {
        Self::NoAuth(NoAuth)
    }

    // Create a new [`AuthAdaptor`] instance with username and password authentication.
    #[inline]
    pub fn password<S: Into<String>>(username: S, password: S) -> Self {
        AuthAdaptor::Password(Password::new(username, password))
    }
}

impl Auth for AuthAdaptor {
    type Output = Result<Extension, AuthError>;

    #[inline]
    fn method(&self) -> Method {
        match self {
            Self::NoAuth(auth) => auth.method(),
            Self::Password(auth) => auth.method(),
        }
    }

    #[inline]
    async fn authenticate(&self, credentials: Option<UsernamePassword>) -> Self::Output {
        match self {
            Self::NoAuth(auth) => auth.authenticate(credentials).await,
            Self::Password(auth) => auth.authenticate(credentials).await,
        }
    }
}

/// No authentication as the socks5 handshake method.
pub struct NoAuth;

impl Auth for NoAuth {
    type Output = Result<Extension, AuthError>;

    #[inline]
    fn method(&self) -> Method {
        Method::NoAuth
    }

    #[inline]
    async fn authenticate(&self, credentials: Option<UsernamePassword>) -> Self::Output {
        if credentials.is_none() {
            Ok(Extension::None)
        } else {
            Err(AuthError::Rejected(
                "unexpected credentials for no-auth method",
            ))
        }
    }
}

/// Username and password as the socks5 handshake method.
pub struct Password {
    username: String,
    password: String,
}

impl Password {
    /// Create a new [`PasswordAuth`] instance with the given username and password.
    pub fn new<S: Into<String>>(username: S, password: S) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl Auth for Password {
    type Output = Result<Extension, AuthError>;

    #[inline]
    fn method(&self) -> Method {
        Method::Password
    }

    async fn authenticate(&self, credentials: Option<UsernamePassword>) -> Self::Output {
        let credentials =
            credentials.ok_or(AuthError::Rejected("username and password are required"))?;
        let is_equal = credentials.username.starts_with(self.username.as_bytes())
            && credentials.password.as_ref() == self.password.as_bytes();
        if is_equal {
            let username = std::str::from_utf8(&credentials.username)
                .map_err(|_| AuthError::Rejected("username or password is incorrect"))?;
            let extension = Extension::try_from(&self.username, username)
                .await
                .map_err(|error| AuthError::Internal(Error::other(error)))?;

            Ok(extension)
        } else {
            Err(AuthError::Rejected("username or password is incorrect"))
        }
    }
}
