use crate::proxy::auth;
use crate::BootArgs;
use cidr::Ipv6Cidr;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use rand::Rng;
use tokio::sync::Semaphore;

use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use super::error::ProxyError;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

pub async fn run(args: BootArgs) -> crate::Result<()> {
    tracing::info!("Listening on http://{}", args.bind);
    let listener = TcpListener::bind(args.bind).await?;
    let http_proxy = Arc::new(HttpProxy::new(args));
    // Limit to 100 concurrent tasks
    let sem = Arc::new(Semaphore::new(100)); 

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let http_proxy = http_proxy.clone();
        let permit = sem.clone().acquire_owned().await;

        tokio::task::spawn(async move {
            let _permit = permit;
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service_fn(move |req| http_proxy.proxy(req)))
                .with_upgrades()
                .await
            {
                tracing::error!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Clone, Copy)]
struct HttpProxy {
    /// Ipv6 subnet, e.g. 2001:db8::/32
    ipv6_subnet: Option<cidr::Ipv6Cidr>,
    /// Fallback address
    fallback: Option<IpAddr>,
}

impl HttpProxy {
    fn new(args: BootArgs) -> Self {
        Self {
            ipv6_subnet: args.ipv6_subnet,
            fallback: args.fallback,
        }
    }

    async fn proxy(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
        tracing::info!("request: {req:?}");

        // Check basic auth
        auth::valid_basic_auth(req.headers())?;

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
            if let Some(addr) = Self::host_addr(req.uri()) {
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

                Ok(Response::new(Self::empty()))
            } else {
                tracing::warn!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(Self::full("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        } else {
            let mut connector = HttpConnector::new();

            match (self.ipv6_subnet, self.fallback) {
                (Some(v6), Some(IpAddr::V4(v4))) => {
                    let v6 = Self::get_rand_ipv6(v6.first_address().into(), v6.network_length());
                    connector.set_local_addresses(v4, v6);
                }
                (Some(v6), None) => {
                    let v6 = Self::get_rand_ipv6(v6.first_address().into(), v6.network_length());
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

    // Create a TCP connection to host:port, build a tunnel between the connection and
    // the upgraded connection
    async fn tunnel(&self, upgraded: Upgraded, addr_str: String) -> std::io::Result<()> {
        for addr in addr_str.to_socket_addrs()? {
            match self.try_connect(addr).await {
                Ok(mut server) => {
                    tracing::info!("tunnel: {} via {}", addr_str, server.local_addr()?);
                    return Self::tunnel_proxy(upgraded, &mut server).await;
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
    async fn try_connect(self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        match (self.ipv6_subnet, self.fallback) {
            (Some(ipv6_cidr), ip_addr) => {
                self.try_connect_with_ipv6_and_fallback(addr, ipv6_cidr, ip_addr)
                    .await
            }
            (None, Some(ip)) => self.try_connect_with_fallback(addr, ip).await,
            _ => TcpStream::connect(addr).await,
        }
    }

    /// Try to connect with ipv6 and fallback to ipv4/ipv6
    async fn try_connect_with_ipv6_and_fallback(
        self,
        addr: SocketAddr,
        v6: Ipv6Cidr,
        ip: Option<IpAddr>,
    ) -> std::io::Result<TcpStream> {
        let socket = TcpSocket::new_v6()?;
        let bind_addr = SocketAddr::new(
            Self::get_rand_ipv6(v6.first_address().into(), v6.network_length()).into(),
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
                    let socket = self.create_socket_for_ip(ip)?;
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
    async fn try_connect_with_fallback(
        self,
        addr: SocketAddr,
        ip: IpAddr,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_for_ip(ip)?;
        let bind_addr = SocketAddr::new(ip, 0);
        socket.bind(bind_addr)?;
        socket.connect(addr).await
    }

    /// Create a socket for ip
    fn create_socket_for_ip(self, ip: IpAddr) -> std::io::Result<TcpSocket> {
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
}
