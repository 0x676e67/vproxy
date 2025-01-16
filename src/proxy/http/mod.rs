mod accept;
pub mod error;
mod genca;
mod server;
mod tls;

use super::ProxyContext;
use server::Server;
use std::path::PathBuf;
use tls::{RustlsAcceptor, RustlsConfig};

pub async fn http_proxy(ctx: ProxyContext) -> crate::Result<()> {
    tracing::info!("HTTP proxy server listening on {}", ctx.bind);

    let mut server = Server::new(ctx)?;
    server
        .http_builder()
        .http1()
        .title_case_headers(true)
        .preserve_header_case(true);

    server.serve().await
}

pub async fn https_proxy(
    ctx: ProxyContext,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> crate::Result<()> {
    tracing::info!("HTTP proxy server listening on {}", ctx.bind);

    // Load TLS configuration
    let config = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => RustlsConfig::from_pem_chain_file(cert, key),
        _ => {
            let (cert, key) = genca::get_self_signed_cert()?;
            RustlsConfig::from_pem(cert, key)
        }
    }?;

    let acceptor = RustlsAcceptor::new(config);
    let mut server = Server::new(ctx)?;
    server
        .http_builder()
        .http1()
        .title_case_headers(true)
        .preserve_header_case(true);

    server.acceptor(acceptor).serve().await
}
