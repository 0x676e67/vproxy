use http::uri::Scheme;
use hyper::{
    rt::{Read, Write},
    Uri,
};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::BufStream;
use tower_service::Service;

use crate::proxy::socks5::{self, proto::UsernamePassword};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Socks(
        #[from]
        #[source]
        socks5::Error,
    ),
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("{0}")]
    Connector(
        #[from]
        #[source]
        BoxedError,
    ),
    #[error("Missing host")]
    MissingHost,
}

/// A future is returned from [`SocksConnector`] service
///
/// [`SocksConnector`]: struct.SocksConnector.html
pub type SocksFuture<R> = Pin<Box<dyn Future<Output = Result<R, Error>> + Send>>;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// A SOCKS5 proxy information and TCP connector
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocksConnector<C> {
    pub proxy_addr: Uri,
    pub auth: Option<UsernamePassword>,
    pub connector: C,
}

impl<C> SocksConnector<C>
where
    C: Service<Uri>,
    C::Response: Read + Write + Send + Unpin,
    C::Error: Into<BoxedError>,
{
    async fn call_async(mut self, target_addr: Uri) -> Result<C::Response, Error> {
        let host = target_addr.host().ok_or(Error::MissingHost)?;
        let port =
            target_addr
                .port_u16()
                .unwrap_or(if target_addr.scheme() == Some(&Scheme::HTTPS) {
                    443
                } else {
                    80
                });

        let stream = self
            .connector
            .call(self.proxy_addr)
            .await
            .map_err(Into::<BoxedError>::into)?;

        let mut buf_stream = BufStream::new(TokioIo::new(stream)); // fixes issue #3
        let _ = socks5::client::connect(&mut buf_stream, (host, port), self.auth).await?;
        Ok(buf_stream.into_inner().into_inner())
    }
}

impl<C> Service<Uri> for SocksConnector<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: Read + Write + Send + Unpin,
    C::Error: Into<BoxedError>,
    C::Future: Send,
{
    type Response = C::Response;
    type Error = Error;
    type Future = SocksFuture<C::Response>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.connector.poll_ready(cx)).map_err(Into::<BoxedError>::into)?;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.call_async(req).await })
    }
}
