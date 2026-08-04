#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    NetworkParse(#[from] cidr::errors::NetworkParseError),

    #[error(transparent)]
    AddressParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    SelfUpdate(#[from] self_update::errors::Error),

    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    Log(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error(transparent)]
    LogParse(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    TaskJoin(#[from] tokio::task::JoinError),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Systemd(#[from] unitbus::Error),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Journal(#[from] sdjournal::SdJournalError),
}
