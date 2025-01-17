#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Http(#[from] http::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    HyperLegacy(#[from] hyper_util::client::legacy::Error),

    #[error("Invalid credentials")]
    ProxyAuthenticationRequired,

    #[error("Forbidden")]
    Forbidden,

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
}
