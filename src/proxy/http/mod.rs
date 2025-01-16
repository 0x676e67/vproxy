pub(super) mod accept;
pub mod error;
pub(super) mod server;
mod tls;

use super::ProxyContext;
use server::Server;
use std::path::PathBuf;
use tls::{RustlsAcceptor, RustlsConfig};
use tokio::net::TcpListener;

pub async fn proxy(
    ctx: ProxyContext,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> crate::Result<()> {
    tracing::info!("Http server listening on {}", ctx.bind);

    let listener = setup_listener(&ctx).await?;

    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        let config = RustlsConfig::from_pem_chain_file(cert, key)?;
        let acceptor = RustlsAcceptor::new(config);
        let mut server = Server::new(listener, ctx);
        server
            .http_builder()
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);

        server.acceptor(acceptor).serve().await
    } else {
        let mut server = Server::new(listener, ctx);
        server
            .http_builder()
            .http1()
            .title_case_headers(true)
            .preserve_header_case(true);

        server.serve().await
    }
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
