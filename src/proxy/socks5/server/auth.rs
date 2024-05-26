use crate::proxy::{
    extension::{Extensions, Whitelist},
    socks5::proto::{handshake::password, AsyncStreamOperation, Method, UsernamePassword},
};
use async_trait::async_trait;
use password::{Request, Response, Status::*};
use std::{
    io::{Error, ErrorKind},
    net::IpAddr,
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
pub struct NoAuth(Vec<IpAddr>);

impl NoAuth {
    /// Creates a new `NoAuth` instance with the given IP whitelist.
    pub fn new(whitelist: Vec<IpAddr>) -> Self {
        Self(whitelist)
    }
}

impl Whitelist for NoAuth {
    fn is_empty(&self) -> bool {
        // Check if the whitelist is empty
        self.0.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        // If whitelist is empty, allow all
        self.0.contains(&ip)
    }
}

#[async_trait]
impl Auth for NoAuth {
    type Output = std::io::Result<(bool, Extensions)>;

    fn method(&self) -> Method {
        Method::NoAuth
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        let socket = stream.peer_addr()?;
        let is_equal = self.contains(socket.ip()) || self.is_empty();
        if !is_equal {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Address {} is not in the whitelist", socket.ip()),
            ));
        }
        Ok((true, Extensions::None))
    }
}

/// Username and password as the socks5 handshake method.
pub struct Password {
    user_pass: UsernamePassword,
    whitelist: Vec<IpAddr>,
}

impl Whitelist for Password {
    fn is_empty(&self) -> bool {
        // Check if the whitelist is empty
        self.whitelist.is_empty()
    }

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
    /// Creates a new `Password` instance with the given username, password, and
    /// IP whitelist.
    pub fn new(username: &str, password: &str, whitelist: Vec<IpAddr>) -> Self {
        Self {
            user_pass: UsernamePassword::new(username, password),
            whitelist,
        }
    }
}

#[async_trait]
impl Auth for Password {
    type Output = std::io::Result<(bool, Extensions)>;

    fn method(&self) -> Method {
        Method::Password
    }

    async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
        let req = Request::retrieve_from_async_stream(stream).await?;
        let socket = stream.peer_addr()?;

        // Check if the username and password are correct
        let is_equal = ({
            req.user_pass.username.starts_with(&self.user_pass.username)
                && req.user_pass.password.eq(&self.user_pass.password)
        }) || self.contains(socket.ip());

        let resp = Response::new(if is_equal { Succeeded } else { Failed });
        resp.write_to_async_stream(stream).await?;
        if is_equal {
            Ok((
                true,
                Extensions::from((
                    self.user_pass.username.as_str(),
                    req.user_pass.username.as_str(),
                )),
            ))
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "username or password is incorrect",
            ))
        }
    }
}
