pub(super) mod accept;
pub mod error;
pub(super) mod server;
mod tls;

use super::ProxyContext;
use server::Server;
use std::path::PathBuf;
use tls::{RustlsAcceptor, RustlsConfig};

pub async fn proxy(
    ctx: ProxyContext,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> crate::Result<()> {
    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        tracing::info!("HTTP proxy server listening on {}", ctx.bind);

        let config = RustlsConfig::from_pem_chain_file(cert, key)?;
        let acceptor = RustlsAcceptor::new(config);
        let mut server = Server::new(ctx)?;
        server
            .http_builder()
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);

        server.acceptor(acceptor).serve().await
    } else {
        tracing::info!("HTTPS proxy server listening on {}", ctx.bind);

        let mut server = Server::new(ctx)?;
        server
            .http_builder()
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);

        server.serve().await
    }
}
