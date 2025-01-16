use crate::proxy::{
    extension::Extension,
    socks5::proto::{handshake::password, AsyncStreamOperation, Method, UsernamePassword},
};
use async_trait::async_trait;
use password::{Request, Response, Status::*};
use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};
use tokio::net::TcpStream;

pub type AuthAdaptor<A> = Arc<dyn Auth<Output = A> + Send + Sync>;

#[async_trait]
pub trait Auth {
    type Output;
    fn method(&self) -> Method;
    async fn execute(&self, stream: &mut TcpStream) -> Self::Output;
}

/// No authentication as the socks5 handshake method.
#[derive(Debug, Default)]
pub struct NoAuth;

#[async_trait]
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
pub struct Password {
    user_pass: UsernamePassword,
}

impl Password {
    /// Creates a new `Password` instance with the given username, password, and
    /// IP whitelist.
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            user_pass: UsernamePassword::new(username, password),
        }
    }
}

#[async_trait]
impl Auth for Password {
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
