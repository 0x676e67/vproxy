pub mod error;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use base64::Engine;
use bytes::Bytes;
use cidr::Ipv6Cidr;
use http::{header, HeaderMap};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    server::conn::http1, service::service_fn, upgrade::Upgraded, Method, Request, Response,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rand::Rng;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use self::error::ProxyError;
use super::{auth::Authentication, ProxyContext};
use crate::proxy::auth::{self, AuthError};

#[derive(Clone)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    pub fn auth_basic_auth_realm(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        match self {
            AuthenticationMethod::None => Ok(()),
            AuthenticationMethod::Password { username, password } => {
                let hv = headers
                    .get(header::PROXY_AUTHORIZATION)
                    .ok_or_else(|| AuthError::MissingCredentials)?;

                // extract basic auth
                let basic_auth = hv
                    .to_str()
                    .map_err(|_| AuthError::InvalidCredentials)?
                    .strip_prefix("Basic ")
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // convert to string
                let auth_bytes = base64::engine::general_purpose::STANDARD
                    .decode(basic_auth.as_bytes())
                    .map_err(|_| AuthError::InvalidCredentials)?;
                let auth_str =
                    String::from_utf8(auth_bytes).map_err(|_| AuthError::InvalidCredentials)?;
                let (auth_username, auth_password) = auth_str
                    .split_once(':')
                    .ok_or_else(|| AuthError::InvalidCredentials)?;

                // check credentials
                if username.ne(auth_username) || password.ne(auth_password) {
                    return Err(AuthError::Unauthorized);
                }

                Ok(())
            }
        }
    }
}

impl Authentication for AuthenticationMethod {
    type Item = ();

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        match self {
            AuthenticationMethod::None => Some(()),
            AuthenticationMethod::Password { username, password } => credentials
                .map(|(u, p)| {
                    if u.eq(username) && p.eq(password) {
                        Some(())
                    } else {
                        None
                    }
                })
                .flatten(),
        }
    }
}

pub async fn run(ctx: ProxyContext) -> crate::Result<()> {
    tracing::info!("Http server listening on {}", ctx.bind);
    let listener = TcpListener::bind(ctx.bind).await?;
    let http_proxy = Arc::new(HttpProxy::from(ctx));

    loop {
        let (stream, socket) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let http_proxy = http_proxy.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let http_proxy = http_proxy.clone();
                        <HttpProxy as Clone>::clone(&http_proxy).proxy(socket, req)
                    }),
                )
                .with_upgrades()
                .await
            {
                tracing::error!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Clone)]
struct HttpProxy {
    /// Authentication type
    auth: AuthenticationMethod,
    /// Ipv6 subnet, e.g. 2001:db8::/32
    ipv6_subnet: Option<cidr::Ipv6Cidr>,
    /// Fallback address
    fallback: Option<IpAddr>,
}

impl From<ProxyContext> for HttpProxy {
    fn from(ctx: ProxyContext) -> Self {
        Self {
            auth: match (ctx.auth.username, ctx.auth.password) {
                (Some(username), Some(password)) => {
                    AuthenticationMethod::Password { username, password }
                }

                _ => AuthenticationMethod::None,
            },
            ipv6_subnet: ctx.ipv6_subnet,
            fallback: ctx.fallback,
        }
    }
}

impl HttpProxy {
    async fn proxy(
        self,
        socket: SocketAddr,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
        tracing::info!("request: {req:?}, {socket:?}", req = req, socket = socket);

        // Check Ip address whitelist or basic auth
        auth::valid_ip_whitelist(socket)
            .or_else(|_| self.auth.auth_basic_auth_realm(req.headers()))?;

        if Method::CONNECT == req.method() {
            // Received an HTTP request like:
            // ```
            // CONNECT www.domain.com:443 HTTP/1.1
            // Host: www.domain.com:443
            // Proxy-Connection: Keep-Alive
            // ```
            //
            // When HTTP method is CONNECT we should return an empty body
            // then we can eventually upgrade the connection and talk a new protocol.
            //
            // Note: only after client received an empty body with STATUS_OK can the
            // connection be upgraded, so we can't return a response inside
            // `on_upgrade` future.
            if let Some(addr) = host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = self.tunnel(upgraded, addr).await {
                                tracing::warn!("server io error: {}", e);
                            };
                        }
                        Err(e) => tracing::warn!("upgrade error: {}", e),
                    }
                });

                Ok(Response::new(empty()))
            } else {
                tracing::warn!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        } else {
            let mut connector = HttpConnector::new();

            match (self.ipv6_subnet, self.fallback) {
                (Some(v6), Some(IpAddr::V4(v4))) => {
                    let v6 = get_rand_ipv6(v6.first_address().into(), v6.network_length());
                    connector.set_local_addresses(v4, v6);
                }
                (Some(v6), None) => {
                    let v6 = get_rand_ipv6(v6.first_address().into(), v6.network_length());
                    connector.set_local_address(Some(v6.into()));
                }
                // ipv4 or ipv6
                (None, Some(ip)) => connector.set_local_address(Some(ip)),
                _ => {}
            }

            let resp = Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(connector)
                .request(req)
                .await?;

            Ok(resp.map(|b| b.boxed()))
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection
    // and the upgraded connection
    async fn tunnel(&self, upgraded: Upgraded, addr_str: String) -> std::io::Result<()> {
        for addr in addr_str.to_socket_addrs()? {
            match self.try_connect(addr).await {
                Ok(mut server) => {
                    tracing::info!("tunnel: {} via {}", addr_str, server.local_addr()?);
                    return tunnel_proxy(upgraded, &mut server).await;
                }
                Err(err) => {
                    tracing::debug!("try connect: {} failed: {}", addr_str, err);
                }
            }
        }

        // All attempts failed
        tracing::warn!("tunnel: {} failed", addr_str);

        Ok(())
    }

    /// Get a socket and a bind address
    async fn try_connect(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        match (self.ipv6_subnet, self.fallback) {
            (Some(ipv6_cidr), ip_addr) => {
                try_connect_with_ipv6_and_fallback(addr, ipv6_cidr, ip_addr).await
            }
            (None, Some(ip)) => try_connect_with_fallback(addr, ip).await,
            _ => TcpStream::connect(addr).await,
        }
    }
}

/// Try to connect with ipv6 and fallback to ipv4/ipv6
async fn try_connect_with_ipv6_and_fallback(
    addr: SocketAddr,
    v6: Ipv6Cidr,
    ip: Option<IpAddr>,
) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v6()?;
    let bind_addr = SocketAddr::new(
        get_rand_ipv6(v6.first_address().into(), v6.network_length()).into(),
        0,
    );
    socket.bind(bind_addr)?;

    // Try to connect with ipv6
    match socket.connect(addr).await {
        Ok(first) => Ok(first),
        Err(err) => {
            tracing::debug!("try connect with ipv6 failed: {}", err);
            if let Some(ip) = ip {
                // Try to connect with fallback ip (ipv4 or ipv6)
                let socket = create_socket_for_ip(ip)?;
                let bind_addr = SocketAddr::new(ip, 0);
                socket.bind(bind_addr)?;
                socket.connect(addr).await
            } else {
                // Try to connect with system default ip
                TcpStream::connect(addr).await
            }
        }
    }
}

/// Try to connect with fallback to ipv4/ipv6
async fn try_connect_with_fallback(addr: SocketAddr, ip: IpAddr) -> std::io::Result<TcpStream> {
    let socket = create_socket_for_ip(ip)?;
    let bind_addr = SocketAddr::new(ip, 0);
    socket.bind(bind_addr)?;
    socket.connect(addr).await
}

/// Create a socket for ip
fn create_socket_for_ip(ip: IpAddr) -> std::io::Result<TcpSocket> {
    match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
}

/// Proxy data between upgraded connection and server
async fn tunnel_proxy(upgraded: Upgraded, server: &mut TcpStream) -> std::io::Result<()> {
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), server).await?;
    tracing::debug!(
        "client wrote {} bytes and received {} bytes",
        from_client,
        from_server
    );
    Ok(())
}

/// Get a random ipv6 address
fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> Ipv6Addr {
    let rand: u128 = rand::thread_rng().gen();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    ipv6.into()
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
