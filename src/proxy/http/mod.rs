mod auth;
pub mod error;

use self::{auth::Authenticator, error::ProxyError};
use super::{auth::Extentions, connect::Connector, ProxyContext};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    server::conn::http1, service::service_fn, upgrade::Upgraded, Method, Request, Response,
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::net::TcpStream;

pub async fn proxy(ctx: ProxyContext) -> crate::Result<()> {
    tracing::info!("Http server listening on {}", ctx.bind);

    let socket = if ctx.bind.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(ctx.bind)?;
    let listener = socket.listen(ctx.concurrent as u32)?;

    // Create a proxy instance
    let proxy = Arc::new(HttpProxy::from(ctx));

    loop {
        let (stream, socket) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let http_proxy = proxy.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
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
    auth: Authenticator,
    /// Connecetor
    connector: Connector,
}

impl From<ProxyContext> for HttpProxy {
    fn from(ctx: ProxyContext) -> Self {
        Self {
            auth: match (ctx.auth.username, ctx.auth.password) {
                (Some(username), Some(password)) => Authenticator::Password {
                    username,
                    password,
                    whitelist: ctx.whitelist,
                },

                _ => Authenticator::None(ctx.whitelist),
            },
            connector: ctx.connector,
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

        // Check if the client is authorized
        let extention = self.auth.authenticate(req.headers(), socket)?;

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
                            if let Err(e) = self.tunnel(upgraded, addr, extention).await {
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
            let resp = Client::builder(TokioExecutor::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(self.connector.new_http_connector(extention))
                .request(req)
                .await?;

            Ok(resp.map(|b| b.boxed()))
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection
    // and the upgraded connection
    async fn tunnel(
        &self,
        upgraded: Upgraded,
        addr_str: String,
        extention: Extentions,
    ) -> std::io::Result<()> {
        for addr in addr_str.to_socket_addrs()? {
            match self.connector.try_connect(addr, extention).await {
                Ok(mut server) => {
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
