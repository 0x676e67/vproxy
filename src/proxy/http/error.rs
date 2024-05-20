use super::auth::AuthError;

/// Proxy Error
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    /// Hyper Error
    #[error("{0:?}")]
    HyperError(#[from] hyper::Error),

    /// Hyper Legacy Error
    #[error("{0:?}")]
    HyperLegacyError(#[from] hyper_util::client::legacy::Error),

    /// Hyper HTTP Error
    #[error("{0:?}")]
    AuthError(#[from] AuthError),

    /// Tokio timeout Error
    #[error("{0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
