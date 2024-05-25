#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    /// Hyper Error
    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    /// Hyper Legacy Error
    #[error(transparent)]
    HyperLegacyError(#[from] hyper_util::client::legacy::Error),

    /// Hyper HTTP Error
    #[error(transparent)]
    AuthError(#[from] super::auth::AuthError),

    /// Tokio timeout Error
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
}
