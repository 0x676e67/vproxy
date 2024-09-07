use std::{path::PathBuf, time::Duration};

use crate::proxy::socks5;

use super::inner::http::{Intercept, Proxy, ProxyConnector};
use super::{
    error::Error,
    inner::socks5::SocksConnector,
    load::{self, ProxyLoadBalancer},
};
use headers::{authorization::Basic, Authorization};
use http::uri::Scheme;
use http::{Request, Response, Uri};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use tokio::net::TcpStream;

pub struct ForwardConnector {
    lb: ProxyLoadBalancer,
    default_http_connector: HttpConnector,
}

impl ForwardConnector {
    pub fn new(path: PathBuf, connect_timeout: u64) -> anyhow::Result<Self> {
        let connect_timeout = Duration::from_secs(connect_timeout);
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect_timeout));
        Ok(Self {
            lb: ProxyLoadBalancer::new(path)?,
            default_http_connector: connector,
        })
    }
}

impl ForwardConnector {
    pub async fn forward(&self, req: Request<Incoming>) -> Result<Response<Incoming>, Error> {
        let inner_proxy = self.lb.next_proxy();
        match inner_proxy.scheme {
            load::InnerScheme::HTTP => {
                let proxy_connector = {
                    let mut proxy = Proxy::new(Intercept::All, inner_proxy.uri);
                    let auth: Option<Authorization<Basic>> = inner_proxy.auth.into();
                    if let Some(auth) = auth {
                        proxy.set_authorization(auth)
                    }
                    let proxy_connector = ProxyConnector::from_proxy_unsecured(
                        self.default_http_connector.clone(),
                        proxy,
                    );
                    proxy_connector
                };

                Client::builder(TokioExecutor::new())
                    .build(proxy_connector)
                    .request(req)
                    .await
                    .map_err(Into::into)
            }
            load::InnerScheme::SOCKS5 => {
                let proxy_connector = SocksConnector {
                    proxy_addr: inner_proxy.uri,
                    auth: inner_proxy.auth.into(),
                    connector: self.default_http_connector.clone(),
                };
                Client::builder(TokioExecutor::new())
                    .build(proxy_connector)
                    .request(req)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    pub async fn forward_tunnel(&self, target_addr: Uri) -> std::io::Result<TcpStream> {
        let inner_proxy = self.lb.next_proxy();
        let mut last_err = None;

        let host = target_addr.host().unwrap();
        let port =
            target_addr
                .port_u16()
                .unwrap_or(if target_addr.scheme() == Some(&Scheme::HTTPS) {
                    443
                } else {
                    80
                });

        match inner_proxy.scheme {
            load::InnerScheme::HTTP => {
                
            }
            load::InnerScheme::SOCKS5 => {
                let proxy_addr = (inner_proxy.host(), inner_proxy.port());
                match TcpStream::connect(proxy_addr).await {
                    Ok(mut stream) => {
                        let connect = socks5::client::connect(
                            &mut stream,
                            (host, port),
                            inner_proxy.auth.clone().into(),
                        )
                        .await?;

                        tracing::info!("socks5 connect {proxy_addr:?} via {connect}");
                        return Ok(stream);
                    }
                    Err(err) => {
                        last_err = Some(err);
                    }
                }
            }
        }

        Err(error(last_err))
    }
}

fn error(last_err: Option<std::io::Error>) -> std::io::Error {
    match last_err {
        Some(e) => {
            tracing::error!("Failed to connect to any resolved address: {}", e);
            e
        }
        None => std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Failed to connect to any resolved address",
        ),
    }
}
