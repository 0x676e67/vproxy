use crate::proxy::{
    auth::Whitelist,
    socks5::proto::{handshake::password, AsyncStreamOperation, Method, UsernamePassword},
};
use as_any::AsAny;
use async_trait::async_trait;
use std::{
    io::{Error, ErrorKind},
    net::IpAddr,
    sync::Arc,
};
use tokio::net::TcpStream;

pub type AuthAdaptor<O> = Arc<dyn Auth<Output = O> + Send + Sync>;

#[async_trait]
pub trait Auth {
    type Output: AsAny;
    fn method(&self) -> Method;
    async fn execute(&self, stream: &mut TcpStream) -> Self::Output;
}

/// No authentication as the socks5 handshake method.
#[derive(Debug, Default)]
pub struct NoAuth;

#[async_trait]
impl Auth for NoAuth {
    type Output = ();

    fn method(&self) -> Method {
        Method::NoAuth
    }

    async fn execute(&self, _: &mut TcpStream) -> Self::Output {}
}

/// Username and password as the socks5 handshake method.
pub struct Password {
    user_pass: UsernamePassword,
    whitelist: Vec<IpAddr>,
}

impl Whitelist for Password {
    fn contains(&self, ip: IpAddr) -> bool {
        // If whitelist is empty, allow all
        if self.whitelist.is_empty() {
            return true;
        } else {
            // Check if the ip is in the whitelist
            return self.whitelist.contains(&ip);
        }
    }
}

impl Password {
    pub fn new(username: &str, password: &str, whitelist: Vec<IpAddr>) -> Self {
        Self {
            user_pass: UsernamePassword::new(username, password),
            whitelist,
        }
    }
}

#[async_trait]
impl Auth for Password {
    type Output = std::io::Result<bool>;

    fn method(&self) -> Method {
        Method::Password
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        use password::{Request, Response, Status::*};
        let req = Request::retrieve_from_async_stream(stream).await?;
        let socket = stream.peer_addr()?;

        let is_equal = (req.user_pass == self.user_pass) || self.contains(socket.ip());
        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            Ok(true)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "username or password is incorrect",
            ))
        }
    }
}
