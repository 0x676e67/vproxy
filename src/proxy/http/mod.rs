mod auth;
pub mod error;

use self::{
    auth::{AuthError, Authenticator},
    error::ProxyError,
};
use super::{connect::Connector, extension::Extensions, ProxyContext};
use bytes::Bytes;
use http::{header, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, upgrade::Upgraded, Method, Request,
    Response,
};
use hyper_util::rt::TokioIo;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};

pub async fn proxy(ctx: ProxyContext) -> crate::Result<()> {
    tracing::info!("Http server listening on {}", ctx.bind);

    let listener = setup_listener(&ctx).await?;
    let proxy = HttpProxy::from(ctx);

    while let Ok((stream, socket)) = listener.accept().await {
        let http_proxy = proxy.clone();
        tokio::spawn(handle_connection(http_proxy, stream, socket));
    }

    Ok(())
}

async fn setup_listener(ctx: &ProxyContext) -> std::io::Result<TcpListener> {
    let socket = if ctx.bind.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(ctx.bind)?;
    socket.listen(ctx.concurrent as u32)
}

async fn handle_connection(proxy: HttpProxy, stream: TcpStream, socket: SocketAddr) {
    let io = TokioIo::new(stream);
    if let Err(err) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| <HttpProxy as Clone>::clone(&proxy).proxy(socket, req)),
        )
        .with_upgrades()
        .await
    {
        tracing::error!("Failed to serve connection: {:?}", err);
    }
}

#[derive(Clone)]
struct HttpProxy(Arc<Authenticator>, Arc<Connector>);

impl From<ProxyContext> for HttpProxy {
    fn from(ctx: ProxyContext) -> Self {
        let auth = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => Authenticator::Password {
                username,
                password,
                whitelist: ctx.whitelist,
            },

            _ => Authenticator::None(ctx.whitelist),
        };

        HttpProxy(Arc::new(auth), Arc::new(ctx.connector))
    }
}

impl HttpProxy {
    async fn proxy(
        self,
        socket: SocketAddr,
        mut req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
        tracing::info!("request: {req:?}, {socket:?}", req = req, socket = socket);

        // Check if the client is authorized
        let extension = match self.0.authenticate(req.headers_mut(), socket) {
            Ok(extension) => extension,
            // If the client is not authorized, return an error response
            Err(e) => return Ok(e.into()),
        };

        if Method::CONNECT == req.method() {
            // Received an HTTP request like:
            // ```
            // CONNECT www.domain.com:443 HTTP/1.1
            // Host: www.domain.com:443
            // Proxy-Connection: Keep-Alive
            // ```
            //
            // When HTTP method is CONNECT we should return an empty body,
            // then we can eventually upgrade the connection and talk a new protocol.
            //
            // Note: only after client received an empty body with STATUS_OK can the
            // connection be upgraded, so we can't return a response inside
            // `on_upgrade` future.
            if let Some(addr) = host_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            if let Err(e) = self.tunnel(upgraded, addr, extension).await {
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
                *resp.status_mut() = StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        } else {
            Ok(self
                .1
                .new_http_request(req, extension)
                .await?
                .map(|b| b.boxed()))
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection
    // and the upgraded connection
    async fn tunnel(
        &self,
        upgraded: Upgraded,
        addr_str: String,
        extension: Extensions,
    ) -> std::io::Result<()> {
        let mut server = {
            let addrs = addr_str.to_socket_addrs()?;
            self.1.try_connect_with_addrs(addrs, extension).await?
        };

        tunnel_proxy(upgraded, &mut server).await
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

impl Into<Response<BoxBody<Bytes, hyper::Error>>> for AuthError {
    fn into(self) -> Response<BoxBody<Bytes, hyper::Error>> {
        match self {
            AuthError::ProxyAuthenticationRequired => Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(header::PROXY_AUTHENTICATE, "Basic realm=\"Proxy\"")
                .body(empty())
                .unwrap(),
            AuthError::Forbidden => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(empty())
                .unwrap(),
        }
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
