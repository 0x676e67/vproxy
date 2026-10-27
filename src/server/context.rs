use std::net::SocketAddr;

use super::{Connector, auth::Source};

/// Server context containing configuration and runtime parameters.
///
/// This struct holds all the necessary configuration for running a proxy server,
/// including network settings, connection limits, timeouts, and authentication.
#[derive(Clone)]
pub struct Context {
    /// The socket address to bind the server to
    pub bind: SocketAddr,

    /// Per-listener accepted TCP sessions and their remaining HTTP work;
    /// MASQUE counts CONNECT-UDP tunnels instead. Must pass validate_concurrent.
    pub concurrent: u32,

    /// Connection timeout in seconds
    pub connect_timeout: u64,

    /// Authentication mode for client connections
    pub(crate) auth: Source,

    /// Network connector for establishing outbound connections
    pub connector: Connector,
}
