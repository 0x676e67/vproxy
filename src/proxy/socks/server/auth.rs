use crate::proxy::{
    extension::Extension,
    socks::proto::{handshake::password, AsyncStreamOperation, Method, UsernamePassword},
};
use password::{Request, Response, Status::*};
use std::{
    future::Future,
    io::{Error, ErrorKind},
};
use tokio::net::TcpStream;

pub trait Auth: Send {
    type Output;
    fn method(&self) -> Method;
    fn execute(&self, stream: &mut TcpStream) -> impl Future<Output = Self::Output> + Send;
}

pub enum AuthAdaptor {
    NoAuth(NoAuth),
    Password(PasswordAuth),
}

impl AuthAdaptor {
    pub fn new_no_auth() -> Self {
        Self::NoAuth(NoAuth)
    }

    pub fn new_password(username: &str, password: &str) -> Self {
        Self::Password(PasswordAuth::new(username, password))
    }
}

impl Auth for AuthAdaptor {
    type Output = std::io::Result<(bool, Extension)>;

    fn method(&self) -> Method {
        match self {
            Self::NoAuth(auth) => auth.method(),
            Self::Password(auth) => auth.method(),
        }
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        match self {
            Self::NoAuth(auth) => auth.execute(stream).await,
            Self::Password(auth) => auth.execute(stream).await,
        }
    }
}

/// No authentication as the socks5 handshake method.
pub struct NoAuth;

impl Auth for NoAuth {
    type Output = std::io::Result<(bool, Extension)>;

    fn method(&self) -> Method {
        Method::NoAuth
    }

    async fn execute(&self, _stream: &mut TcpStream) -> Self::Output {
        Ok((true, Extension::None))
    }
}

/// Username and password as the socks5 handshake method.
pub struct PasswordAuth {
    user_pass: UsernamePassword,
}

impl PasswordAuth {
    /// Creates a new `Password` instance with the given username, password, and
    /// IP whitelist.
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            user_pass: UsernamePassword::new(username, password),
        }
    }
}

impl Auth for PasswordAuth {
    type Output = std::io::Result<(bool, Extension)>;

    fn method(&self) -> Method {
        Method::Password
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        let req = Request::retrieve_from_async_stream(stream).await?;

        // Check if the username and password are correct
        let is_equal = req.user_pass.username.starts_with(&self.user_pass.username)
            && req.user_pass.password.eq(&self.user_pass.password);

        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            let extension =
                Extension::try_from((&self.user_pass.username, &req.user_pass.username))
                    .await
                    .map_err(|_| Error::new(ErrorKind::Other, "failed to parse extension"))?;

            Ok((true, extension))
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "username or password is incorrect",
            ))
        }
    }
}
