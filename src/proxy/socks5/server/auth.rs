use crate::proxy::{
    auth,
    socks5::proto::{handshake::password, AsyncStreamOperation, AuthMethod, UsernamePassword},
};
use as_any::AsAny;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::TcpStream;

pub type AuthAdaptor<O> = Arc<dyn Auth<Output = O> + Send + Sync>;

#[async_trait]
pub trait Auth {
    type Output: AsAny;
    fn auth_method(&self) -> AuthMethod;
    async fn execute(&self, stream: &mut TcpStream) -> Self::Output;
}

/// No authentication as the socks5 handshake method.
#[derive(Debug, Default)]
pub struct NoAuth;

#[async_trait]
impl Auth for NoAuth {
    type Output = ();

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::NoAuth
    }

    async fn execute(&self, _: &mut TcpStream) -> Self::Output {}
}

/// Username and password as the socks5 handshake method.
pub struct Password(UsernamePassword);

impl Password {
    pub fn new(username: &str, password: &str) -> Self {
        let user_pass = UsernamePassword::new(username, password);
        Self(user_pass)
    }
}

#[async_trait]
impl Auth for Password {
    type Output = std::io::Result<bool>;

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::Password
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        use password::{Request, Response, Status::*};
        let req = Request::retrieve_from_async_stream(stream).await?;
        let socket = stream.peer_addr()?;

        let is_equal = (req.user_pass == self.0) || auth::authenticate_ip(socket).is_ok();
        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            Ok(true)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "username or password is incorrect",
            ))
        }
    }
}
