use std::{future::Future, io::Error};

use password::{Request, Response, Status::*};
use tokio::net::TcpStream;

use crate::server::{
    extension::Extension,
    socks::proto::{AsyncStreamOperation, Method, UsernamePassword, handshake::password},
};

/// Trait for SOCKS authentication methods.
pub trait Auth: Send {
    type Output;

    /// Returns the SOCKS authentication method type.
    fn method(&self) -> Method;

    /// Executes the authentication process with the client.
    fn execute(&self, stream: &mut TcpStream) -> impl Future<Output = Self::Output> + Send;
}

/// Unified interface for different SOCKS authentication methods.
#[non_exhaustive]
pub enum AuthAdaptor {
    NoAuth(NoAuth),
    PasswordAuth(PasswordAuth),
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
        AuthAdaptor::PasswordAuth(PasswordAuth::new(username, password))
    }
}

impl Auth for AuthAdaptor {
    type Output = std::io::Result<(bool, Extension)>;

    #[inline]
    fn method(&self) -> Method {
        match self {
            Self::NoAuth(auth) => auth.method(),
            Self::PasswordAuth(auth) => auth.method(),
        }
    }

    #[inline]
    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        match self {
            Self::NoAuth(auth) => auth.execute(stream).await,
            Self::PasswordAuth(auth) => auth.execute(stream).await,
        }
    }
}

/// No authentication as the socks5 handshake method.
pub struct NoAuth;

impl Auth for NoAuth {
    type Output = std::io::Result<(bool, Extension)>;

    #[inline]
    fn method(&self) -> Method {
        Method::NoAuth
    }

    #[inline]
    async fn execute(&self, _stream: &mut TcpStream) -> Self::Output {
        Ok((true, Extension::None))
    }
}

/// Username and password as the socks5 handshake method.
pub struct PasswordAuth {
    inner: UsernamePassword,
}

impl PasswordAuth {
    /// Create a new [`PasswordAuth`] instance with the given username and password.
    pub fn new<S: Into<String>>(username: S, password: S) -> Self {
        Self {
            inner: UsernamePassword::new(username, password),
        }
    }
}

impl Auth for PasswordAuth {
    type Output = std::io::Result<(bool, Extension)>;

    #[inline]
    fn method(&self) -> Method {
        Method::Password
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        let req = Request::retrieve_from_async_stream(stream).await?;

        // Check if the username and password are correct
        let is_equal = req.user_pass.username.starts_with(&self.inner.username)
            && req.user_pass.password.eq(&self.inner.password);

        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            let extension = Extension::try_from(&self.inner.username, req.user_pass.username)
                .await
                .map_err(|_| Error::other("failed to parse extension"))?;

            Ok((true, extension))
        } else {
            Err(Error::other("username or password is incorrect"))
        }
    }
}
