use super::auth::Extensions;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use hyper_util::client::legacy::connect::HttpConnector;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{lookup_host, TcpSocket, TcpStream};

/// `Connector` struct is used to create HTTP connectors, optionally configured
/// with an IPv6 CIDR and a fallback IP address.
#[derive(Clone)]
pub struct Connector {
    /// Optional IPv6 CIDR (Classless Inter-Domain Routing), used to optionally
    /// configure an IPv6 address.
    cidr: Option<IpCidr>,
    /// Optional IP address as a fallback option in case of connection failure.
    fallback: Option<IpAddr>,
}

impl Connector {
    /// Constructs a new `Connector` instance, accepting optional IPv6 CIDR and
    /// fallback IP address as parameters.
    pub(super) fn new(cidr: Option<IpCidr>, fallback: Option<IpAddr>) -> Self {
        Connector { cidr, fallback }
    }

    /// Generates a new `HttpConnector` based on the configuration. This method
    /// configures the connector considering the IPv6 CIDR and fallback IP
    /// address.
    pub fn new_http_connector(&self, extention: Extensions) -> HttpConnector {
        let mut connector = HttpConnector::new();

        match (self.cidr, self.fallback) {
            (Some(IpCidr::V4(cidr)), Some(IpAddr::V6(v6))) => {
                let v4 = assign_ipv4_from_extention(&cidr, extention);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V4(cidr)), None) => {
                let v4 = assign_ipv4_from_extention(&cidr, extention);
                connector.set_local_address(Some(v4.into()));
            }
            (Some(IpCidr::V6(cidr)), Some(IpAddr::V4(v4))) => {
                let v6 = assign_ipv6_from_extention(&cidr, extention);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V6(v6)), None) => {
                let v6 = assign_ipv6_from_extention(&v6, extention);
                connector.set_local_address(Some(v6.into()));
            }
            // ipv4 or ipv6
            (None, Some(ip)) => connector.set_local_address(Some(ip)),
            _ => {}
        }

        connector
    }

    /// Attempts to establish a connection to a given domain and port.
    /// It first resolves the domain, then tries to connect to each resolved
    /// address, until it successfully connects to an address or has tried
    /// all addresses. If all connection attempts fail, it will return the
    /// error from the last attempt. If no connection attempts were made, it
    /// will return a new `Error` object.
    pub async fn try_connect_for_domain(
        &self,
        domain: String,
        port: u16,
        extention: Extensions,
    ) -> std::io::Result<TcpStream> {
        let mut last_err = None;

        for target_addr in lookup_host((domain, port)).await? {
            match self.try_connect(target_addr, extention).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            };
        }

        match last_err {
            Some(e) => Err(e),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Failed to connect to any resolved address",
            )),
        }
    }

    /// Attempts to establish a connection to a given SocketAddr.
    /// If an IPv6 subnet and a fallback IP are provided, it will attempt to
    /// connect using them. If no IPv6 subnet is provided but a fallback IP
    /// is, it will attempt to connect using the fallback IP. If neither are
    /// provided, it will attempt to connect directly to the given SocketAddr.
    pub async fn try_connect(
        &self,
        addr: SocketAddr,
        extention: Extensions,
    ) -> std::io::Result<TcpStream> {
        match (self.cidr, self.fallback) {
            (Some(cidr), ip_addr) => {
                try_connect_with_ipv6_and_fallback(addr, cidr, ip_addr, extention).await
            }
            (None, Some(ip)) => try_connect_with_fallback(addr, ip).await,
            _ => TcpStream::connect(addr).await,
        }
        .and_then(|stream| {
            tracing::info!("connect {} via {}", addr, stream.local_addr()?);
            Ok(stream)
        })
    }
}

/// Try to connect with ipv6 and fallback to ipv4/ipv6
async fn try_connect_with_ipv6_and_fallback(
    target_addr: SocketAddr,
    cidr: IpCidr,
    fallback: Option<IpAddr>,
    extention: Extensions,
) -> std::io::Result<TcpStream> {
    let (bind, socket) = match cidr {
        IpCidr::V4(cidr) => {
            let socket = TcpSocket::new_v4()?;
            (
                IpAddr::V4(assign_ipv4_from_extention(&cidr, extention)),
                socket,
            )
        }
        IpCidr::V6(cidr) => {
            let socket = TcpSocket::new_v6()?;
            (
                IpAddr::V6(assign_ipv6_from_extention(&cidr, extention)),
                socket,
            )
        }
    };
    socket.bind(SocketAddr::new(bind, 0))?;

    // Try to connect with ipv6
    match socket.connect(target_addr).await {
        Ok(first) => Ok(first),
        Err(err) => {
            tracing::debug!("try connect with ipv6 failed: {}", err);
            if let Some(ip) = fallback {
                // Try to connect with fallback ip (ipv4 or ipv6)
                let socket = create_socket_for_ip(ip)?;
                let bind_addr = SocketAddr::new(ip, 0);
                socket.bind(bind_addr)?;
                socket.connect(target_addr).await
            } else {
                // Try to connect with system default ip
                TcpStream::connect(target_addr).await
            }
        }
    }
}

/// Try to connect with fallback to ipv4/ipv6
async fn try_connect_with_fallback(
    target_addr: SocketAddr,
    ip: IpAddr,
) -> std::io::Result<TcpStream> {
    let socket = create_socket_for_ip(ip)?;
    let bind_addr = SocketAddr::new(ip, 0);
    socket.bind(bind_addr)?;
    socket.connect(target_addr).await
}

/// Create a socket for ip
fn create_socket_for_ip(ip: IpAddr) -> std::io::Result<TcpSocket> {
    match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
}

/// Assigns an IPv4 address based on the provided CIDR and extension.
/// If the extension is a Session with an ID, the function generates a
/// deterministic IPv4 address within the CIDR range using a murmurhash of the
/// ID. The network part of the address is preserved, and the host part is
/// generated from the hash. If the extension is not a Session, the function
/// generates a random IPv4 address within the CIDR range.
fn assign_ipv4_from_extention(cidr: &Ipv4Cidr, extention: Extensions) -> Ipv4Addr {
    match extention {
        Extensions::Session((a, _)) => {
            // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
            // the non-variable part
            let subnet_mask = !((1u32 << (32 - cidr.network_length())) - 1);
            let base_ip_bits = u32::from(cidr.first_address()) & subnet_mask;
            let capacity = 2u32.pow(32 - cidr.network_length() as u32) - 1;
            let ip_num = base_ip_bits | ((a as u32) % capacity);
            return Ipv4Addr::from(ip_num);
        }
        _ => {}
    }

    assign_rand_ipv4(cidr.first_address().into(), cidr.network_length())
}

/// Assigns an IPv6 address based on the provided CIDR and extension.
/// If the extension is a Session with an ID, the function generates a
/// deterministic IPv6 address within the CIDR range using a murmurhash of the
/// ID. The network part of the address is preserved, and the host part is
/// generated from the hash. If the extension is not a Session, the function
/// generates a random IPv6 address within the CIDR range.
fn assign_ipv6_from_extention(cidr: &Ipv6Cidr, extention: Extensions) -> Ipv6Addr {
    match extention {
        Extensions::Session((a, b)) => {
            let combined = ((a as u128) << 64) | (b as u128);
            // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
            // the non-variable part
            let subnet_mask = !((1u128 << (128 - cidr.network_length())) - 1);
            let base_ip_bits = u128::from(cidr.first_address()) & subnet_mask;
            let capacity = 2u128.pow(128 - cidr.network_length() as u32) - 1;
            let ip_num = base_ip_bits | (combined % capacity);
            return Ipv6Addr::from(ip_num);
        }
        _ => {}
    }

    assign_rand_ipv6(cidr.first_address().into(), cidr.network_length())
}

/// Generates a random IPv4 address within the specified subnet.
/// The subnet is defined by the initial IPv4 address and the prefix length.
/// The network part of the address is preserved, and the host part is randomly
/// generated.
fn assign_rand_ipv4(mut ipv4: u32, prefix_len: u8) -> Ipv4Addr {
    let rand: u32 = rand::thread_rng().gen();
    let net_part = (ipv4 >> (32 - prefix_len)) << (32 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv4 = net_part | host_part;
    ipv4.into()
}

/// Generates a random IPv6 address within the specified subnet.
/// The subnet is defined by the initial IPv6 address and the prefix length.
/// The network part of the address is preserved, and the host part is randomly
/// generated.
fn assign_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> Ipv6Addr {
    let rand: u128 = rand::thread_rng().gen();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    ipv6.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::murmur;
    use std::str::FromStr;

    #[test]
    fn test_generate_ipv6_from_cidr() {
        let cidr = Ipv6Cidr::from_str("2001:db8::/48").unwrap();
        let session_len = 32;
        let mut sessions = Vec::new();

        for x in 0..session_len {
            let s = x.to_string();
            sessions.push(Extensions::Session(murmur::murmurhash3_x64_128(
                s.as_bytes(),
                s.len() as u64,
            )));
        }

        let mut result = Vec::new();
        for x in &mut sessions {
            result.push(assign_ipv6_from_extention(&cidr, x.clone()));
        }

        let mut check = Vec::new();
        for x in &mut sessions {
            check.push(assign_ipv6_from_extention(&cidr, x.clone()));
        }

        for x in &result {
            assert!(check.contains(x), "IP {} not found in check", x);
        }
    }

    #[test]
    fn test_generate_ipv4_from_cidr() {
        let cidr = Ipv4Cidr::from_str("192.168.0.0/16").unwrap();
        let session_len = 32;
        let mut sessions = Vec::new();

        for x in 0..session_len {
            let s = x.to_string();
            sessions.push(Extensions::Session(murmur::murmurhash3_x64_128(
                s.as_bytes(),
                s.len() as u64,
            )));
        }

        let mut result = Vec::new();
        for x in &mut sessions {
            result.push(assign_ipv4_from_extention(&cidr, x.clone()));
        }

        let mut check = Vec::new();
        for x in &mut sessions {
            check.push(assign_ipv4_from_extention(&cidr, x.clone()));
        }

        for x in &result {
            assert!(check.contains(x), "IP {} not found in check", x);
        }
    }
}
