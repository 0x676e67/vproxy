#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    HttpError(#[from] http::Error),

    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    #[error(transparent)]
    HyperLegacyError(#[from] hyper_util::client::legacy::Error),

    #[error("Invalid credentials")]
    ProxyAuthenticationRequired,

    #[error("Forbidden")]
    Forbidden,

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
}
