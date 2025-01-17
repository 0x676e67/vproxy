use auth::Authenticator;

use super::accept::Accept;
use super::error::Error;
use crate::proxy::http::accept::DefaultAcceptor;
use crate::proxy::{connect::Connector, extension::Extension, Context};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper::{body::Incoming, upgrade::Upgraded, Method, Request, Response};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

/// HTTP server.
pub struct Server<A = DefaultAcceptor> {
    acceptor: A,
    builder: Builder<TokioExecutor>,
    listener: TcpListener,
    http_proxy: Handler,
}

impl Server {
    /// Create a server from ProxyContext.
    pub fn new(ctx: Context) -> std::io::Result<Self> {
        let socket = if ctx.bind.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;

        let listener = socket.listen(ctx.concurrent as u32)?;
        let acceptor = DefaultAcceptor::new();
        let builder = Builder::new(TokioExecutor::new());
        let http_proxy = Handler::from(ctx);

        Ok(Self {
            acceptor,
            builder,
            listener,
            http_proxy,
        })
    }
}

impl<A> Server<A>
where
    A: Accept<TcpStream> + Clone + Send + Sync + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Future: Send,
{
    /// Overwrite acceptor.
    pub fn acceptor<Acceptor>(self, acceptor: Acceptor) -> Server<Acceptor> {
        Server {
            acceptor,
            builder: self.builder,
            listener: self.listener,
            http_proxy: self.http_proxy,
        }
    }

    /// Returns a mutable reference to the Http builder.
    pub fn http_builder(&mut self) -> &mut Builder<TokioExecutor> {
        &mut self.builder
    }

    /// Serve the proxy.
    pub(super) async fn serve(self) -> crate::Result<()> {
        let mut incoming = self.listener;
        let acceptor = self.acceptor;
        let builder = self.builder;
        let proxy = self.http_proxy;

        loop {
            let (tcp_stream, socket_addr) = tokio::select! {
                biased;
                result = accept(&mut incoming) => result,
            };

            let proxy = proxy.clone();
            let acceptor = acceptor.clone();
            let builder = builder.clone();

            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp_stream).await {
                    if let Err(err) = builder
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            service_fn(|req| {
                                <Handler as Clone>::clone(&proxy).proxy(socket_addr, req)
                            }),
                        )
                        .await
                    {
                        tracing::error!("Failed to serve connection: {:?}", err);
                    }
                }
            });
        }
    }
}

async fn accept(listener: &mut TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(value) => return value,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(super) fn io_other<E: Into<BoxError>>(error: E) -> io::Error {
    io::Error::new(ErrorKind::Other, error)
}

#[derive(Clone)]
struct Handler {
    inner: Arc<InnerHandler>,
}

struct InnerHandler {
    authenticator: Authenticator,
    connector: Connector,
}

impl From<Context> for Handler {
    fn from(ctx: Context) -> Self {
        let auth = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => Authenticator::Password { username, password },

            _ => Authenticator::None,
        };

        Handler {
            inner: Arc::new(InnerHandler {
                authenticator: auth,
                connector: ctx.connector,
            }),
        }
    }
}

impl Handler {
    async fn proxy(
        self,
        socket: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        tracing::debug!("Received request socket: {:?}, req: {:?}", socket, req);

        // Check if the client is authorized
        let extension = match self.inner.authenticator.authenticate(req.headers()).await {
            Ok(extension) => extension,
            // If the client is not authorized, return an error response
            Err(e) => return Ok(e.try_into()?),
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
            self.inner
                .connector
                .http_request(req, extension)
                .await
                .map(|res| res.map(|b| b.boxed()))
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection
    // and the upgraded connection
    async fn tunnel(
        &self,
        upgraded: Upgraded,
        addr_str: String,
        extension: Extension,
    ) -> std::io::Result<()> {
        let mut server = {
            let addrs = addr_str.to_socket_addrs()?;
            self.inner
                .connector
                .try_connect_with_addrs(addrs, extension)
                .await?
        };

        match tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server).await {
            Ok((from_client, from_server)) => {
                tracing::debug!(
                    "client wrote {} bytes and received {} bytes",
                    from_client,
                    from_server
                );
            }
            Err(err) => {
                tracing::debug!("tunnel error: {}", err);
            }
        }

        drop(server);

        Ok(())
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

pub(super) mod auth {
    use super::{empty, Error};
    use crate::proxy::extension::Extension;
    use base64::Engine;
    use bytes::Bytes;
    use http::{header, HeaderMap, Response, StatusCode};
    use http_body_util::combinators::BoxBody;

    impl TryInto<Response<BoxBody<Bytes, hyper::Error>>> for Error {
        type Error = http::Error;
        fn try_into(self) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Self::Error> {
            match self {
                Error::ProxyAuthenticationRequired => Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(header::PROXY_AUTHENTICATE, "Basic realm=\"Proxy\"")
                    .body(empty()),
                Error::Forbidden => Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty()),
                _ => Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(empty()),
            }
        }
    }

    /// Enum representing different types of authenticators.
    #[derive(Clone)]
    pub enum Authenticator {
        /// No authentication with an IP whitelist.
        None,
        /// Password authentication with a username, password, and IP whitelist.
        Password { username: String, password: String },
    }

    impl Authenticator {
        pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Extension, Error> {
            match self {
                Authenticator::None => Extension::try_from_headers(headers)
                    .await
                    .map_err(|_| Error::Forbidden),
                Authenticator::Password {
                    username, password, ..
                } => {
                    // Extract basic auth
                    let auth_str = option_ext(headers).ok_or(Error::ProxyAuthenticationRequired)?;
                    // Find last ':' index
                    let last_colon_index = auth_str
                        .rfind(':')
                        .ok_or(Error::ProxyAuthenticationRequired)?;
                    let (auth_username, auth_password) = auth_str.split_at(last_colon_index);
                    let auth_password = &auth_password[1..];

                    // Check if the username and password are correct
                    let is_equal =
                        auth_username.starts_with(username) && auth_password.eq(password);

                    // Check credentials
                    if is_equal {
                        let extensions = Extension::try_from((username, auth_username))
                            .await
                            .map_err(|_| Error::Forbidden)?;
                        Ok(extensions)
                    } else {
                        Err(Error::Forbidden)
                    }
                }
            }
        }
    }

    fn option_ext(headers: &HeaderMap) -> Option<String> {
        let basic_auth = headers
            .get(header::PROXY_AUTHORIZATION)
            .and_then(|hv| hv.to_str().ok())
            .and_then(|s| s.strip_prefix("Basic "))?;

        let auth_bytes = base64::engine::general_purpose::STANDARD
            .decode(basic_auth.as_bytes())
            .ok()?;

        String::from_utf8(auth_bytes).ok()
    }
}
