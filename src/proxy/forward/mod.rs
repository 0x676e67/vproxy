mod auth;
mod connect;
pub mod error;
mod inner;
mod load;

use self::{auth::Authenticator, error::Error};
use super::ForwardProxyContext;
use bytes::Bytes;
pub use connect::ForwardConnector;
use http::Uri;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, upgrade::Upgraded, Method, Request,
    Response,
};
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};

pub async fn proxy(ctx: ForwardProxyContext) -> crate::Result<()> {
    tracing::info!("Http server listening on {}", ctx.bind);

    let listener = setup_listener(&ctx).await?;
    let proxy = HttpProxy::from(ctx);

    while let Ok((stream, socket)) = listener.accept().await {
        let http_proxy = proxy.clone();
        tokio::spawn(handle_connection(http_proxy, stream, socket));
    }

    Ok(())
}

async fn setup_listener(ctx: &ForwardProxyContext) -> std::io::Result<TcpListener> {
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
struct HttpProxy(Arc<(Authenticator, ForwardConnector)>);

impl From<ForwardProxyContext> for HttpProxy {
    fn from(ctx: ForwardProxyContext) -> Self {
        let auth = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => Authenticator::Password {
                username,
                password,
                whitelist: ctx.whitelist,
            },

            _ => Authenticator::None(ctx.whitelist),
        };

        HttpProxy(Arc::new((auth, ctx.connector)))
    }
}

impl HttpProxy {
    async fn proxy(
        self,
        socket: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        tracing::info!("{req:?}, {socket:?}", req = req, socket = socket);

        // Check if the client is authorized
        match self.0 .0.authenticate(req.headers().clone(), socket).await {
            Ok(extension) => extension,
            // If the client is not authorized, return an error response
            Err(e) => return Ok(e.try_into()?),
        };

        if Method::CONNECT == req.method() {
            tokio::task::spawn(async move {
                let uri = req.uri().clone();
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = self.tunnel(upgraded, uri).await {
                            tracing::warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => tracing::warn!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        } else {
            Ok(self.0 .1.forward(req).await?.map(|b| b.boxed()))
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection
    // and the upgraded connection
    async fn tunnel(&self, upgraded: Upgraded, uri: Uri) -> std::io::Result<()> {
        let mut server = { self.0 .1.forward_tunnel(uri).await? };

        let (from_client, from_server) =
            tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server).await?;
        tracing::debug!(
            "client wrote {} bytes and received {} bytes",
            from_client,
            from_server
        );

        Ok(())
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
