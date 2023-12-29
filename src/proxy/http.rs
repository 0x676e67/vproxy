use crate::support::TokioIo;
use crate::BootArgs;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rand::Rng;

use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use tokio::net::{TcpListener, TcpSocket, TcpStream};

pub(super) async fn run(args: BootArgs) -> crate::Result<()> {
    tracing::info!("Listening on http://{}", args.bind);
    let listener = TcpListener::bind(args.bind).await?;
    let http_proxy = Arc::new(HttpProxy::new(args));

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let http_proxy = http_proxy.clone();
        tokio::task::spawn(async move {
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
    ) -> Result<
        Response<BoxBody<Bytes, hyper::Error>>,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {
        tracing::info!("request: {req:?}");

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

            let client = Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(connector);

            let resp = client.request(req).await?.map(|b| b.boxed());
            Ok(resp)
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
            (Some(v6), _) => {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = SocketAddr::new(
                    Self::get_rand_ipv6(v6.first_address().into(), v6.network_length()).into(),
                    0,
                );
                socket.bind(bind_addr)?;
                Ok(socket.connect(bind_addr).await?)
            }
            (_, Some(IpAddr::V4(v4))) => {
                let socket = TcpSocket::new_v4()?;
                let bind_addr = SocketAddr::new(IpAddr::V4(v4), 0);
                socket.bind(bind_addr)?;
                Ok(socket.connect(bind_addr).await?)
            }
            (_, Some(IpAddr::V6(v6))) => {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = SocketAddr::new(IpAddr::V6(v6), 0);
                socket.bind(bind_addr)?;
                Ok(socket.connect(bind_addr).await?)
            }
            _ => Ok(TcpStream::connect(addr).await?),
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

    fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> Ipv6Addr {
        let rand: u128 = rand::thread_rng().gen();
        let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
        let host_part = (rand << prefix_len) >> prefix_len;
        ipv6 = net_part | host_part;
        ipv6.into()
    }
}
