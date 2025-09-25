use std::net::SocketAddr;

use super::{AuthMode, Connector};

/// Server context containing configuration and runtime parameters.
///
/// This struct holds all the necessary configuration for running a proxy server,
/// including network settings, connection limits, timeouts, and authentication.
#[derive(Clone)]
pub struct Context {
    /// The socket address to bind the server to
    pub bind: SocketAddr,

    /// Maximum number of concurrent connections allowed
    pub concurrent: u32,

    /// Connection timeout in seconds
    pub connect_timeout: u64,

    /// Enable SO_REUSEADDR for server listening socket
    pub reuseaddr: Option<bool>,

    /// Enable SO_REUSEPORT for server listening socket
    pub reuseport: Option<bool>,

    /// Authentication mode for client connections
    pub auth: AuthMode,

    /// Network connector for establishing outbound connections
    pub connector: Connector,
}
