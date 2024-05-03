use crate::BootArgs;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::OnceCell;

/// Ip address whitelist
static IP_WHITELIST: OnceCell<Option<Vec<IpAddr>>> = OnceCell::const_new();

/// Init ip whitelist
pub fn init_ip_whitelist(args: &BootArgs) {
    // Set ip whitelist
    if !args.whitelist.is_empty() {
        IP_WHITELIST
            .set(Some(args.whitelist.clone()))
            .expect("IP_WHITELIST should be set only once");
        tracing::info!("IP whitelist: {:?}", args.whitelist);
    }
}

/// Valid Ip address whitelist
pub fn authenticate_ip(socket: SocketAddr) -> bool {
    match IP_WHITELIST.get() {
        Some(Some(ip)) => ip.contains(&socket.ip()),
        Some(None) | None => true,
    }
}
