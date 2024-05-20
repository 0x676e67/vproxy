use super::{auth::Extensions, http::error::ProxyError};
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use http::{Request, Response};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use rand::Rng;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{lookup_host, TcpSocket, TcpStream},
    time::timeout,
};

/// `Connector` struct is used to create HTTP connectors, optionally configured
/// with an IPv6 CIDR and a fallback IP address.
#[derive(Clone)]
pub struct Connector {
    /// Optional IPv6 CIDR (Classless Inter-Domain Routing), used to optionally
    /// configure an IPv6 address.
    cidr: Option<IpCidr>,
    /// Optional IP address as a fallback option in case of connection failure.
    fallback: Option<IpAddr>,
    /// Connect timeout in milliseconds.
    connect_timeout: Duration,
}

impl Connector {
    /// Constructs a new `Connector` instance, accepting optional IPv6 CIDR and
    /// fallback IP address as parameters.
    pub(super) fn new(
        cidr: Option<IpCidr>,
        fallback: Option<IpAddr>,
        connect_timeout: u64,
    ) -> Self {
        Connector {
            cidr,
            fallback,
            connect_timeout: Duration::from_secs(connect_timeout),
        }
    }

    /// Asynchronously creates and sends a new HTTP request with custom local addresses.
    ///
    /// This method constructs an `HttpConnector` and sets its local addresses based on
    /// the provided CIDR and fallback IP configuration. It then sends the request using
    /// a hyper `Client` and returns the response or a `ProxyError` if the request fails.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request to be forwarded.
    /// * `extension` - Additional data used for setting local addresses based on CIDR.
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response on success, or a `ProxyError` on failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let response = proxy.new_http_request(request, extensions).await?;
    /// ```
    ///
    /// # Details
    ///
    /// The method checks the provided CIDR and fallback IP configuration and sets the
    /// local addresses of the connector accordingly:
    ///
    /// * If both CIDR (IPv4) and fallback (IPv6) are provided, it assigns a local IPv4
    ///   address from the CIDR and sets both IPv4 and IPv6 addresses.
    /// * If only CIDR (IPv4) is provided, it assigns a local IPv4 address from the CIDR
    ///   and sets it.
    /// * If both CIDR (IPv6) and fallback (IPv4) are provided, it assigns a local IPv6
    ///   address from the CIDR and sets both IPv4 and IPv6 addresses.
    /// * If only CIDR (IPv6) is provided, it assigns a local IPv6 address from the CIDR
    ///   and sets it.
    /// * If no CIDR is provided but a fallback IP is present, it sets the fallback IP
    ///   address.
    ///
    /// The request is sent with a timeout specified by `self.connect_timeout`.
    pub async fn new_http_request(
        &self,
        req: Request<Incoming>,
        extension: Extensions,
    ) -> Result<Response<Incoming>, ProxyError> {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(self.connect_timeout));

        match (self.cidr, self.fallback) {
            (Some(IpCidr::V4(cidr)), Some(IpAddr::V6(v6))) => {
                let v4 = assign_ipv4_from_extension(&cidr, extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V4(cidr)), None) => {
                let v4 = assign_ipv4_from_extension(&cidr, extension);
                connector.set_local_address(Some(v4.into()));
            }
            (Some(IpCidr::V6(cidr)), Some(IpAddr::V4(v4))) => {
                let v6 = assign_ipv6_from_extension(&cidr, extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V6(cidr)), None) => {
                let v6 = assign_ipv6_from_extension(&cidr, extension);
                connector.set_local_address(Some(v6.into()));
            }
            // ipv4 or ipv6
            (None, Some(ip)) => connector.set_local_address(Some(ip)),
            _ => {}
        }

        let resp = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(connector)
            .request(req)
            .await?;

        Ok(resp)
    }

    /// Attempts to establish a connection to a given domain and port.
    ///
    /// This function first resolves the domain, then tries to connect to each
    /// resolved address, until it successfully connects to an address or
    /// has tried all addresses. If all connection attempts fail, it will
    /// return the error from the last attempt. If no connection attempts
    /// were made, it will return a new `Error` object.
    ///
    /// # Arguments
    ///
    /// * `domain` - The target domain to connect to.
    /// * `port` - The target port to connect to.
    /// * `extension` - Extensions used to assign an IP address from the CIDR.
    ///
    /// # Returns
    ///
    /// * `std::io::Result<TcpStream>` - The established TCP connection, or an
    ///   error if the connection failed.
    ///
    /// # Example
    ///
    /// ```
    /// let domain = "example.com".to_string();
    /// let port = 80;
    /// let extension = Extensions::new();
    /// let stream = try_connect_for_domain((domain, port), extension)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn try_connect_for_domain(
        &self,
        host: (String, u16),
        extension: Extensions,
    ) -> std::io::Result<TcpStream> {
        let mut last_err = None;

        for target_addr in lookup_host(host).await? {
            match self.try_connect(target_addr, extension).await {
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

    /// Tries to establish a TCP connection to a given SocketAddr.
    ///
    /// This function attempts to establish a connection in the following order:
    /// 1. If an IPv6 subnet is provided, it will attempt to connect using the
    ///    subnet.
    /// 2. If no IPv6 subnet is provided but a fallback IP is, it will attempt
    ///    to connect using the fallback IP.
    /// 3. If neither a subnet nor a fallback IP are provided, it will attempt
    ///    to connect directly to the given SocketAddr.
    ///
    /// # Arguments
    ///
    /// * `addr` - The target socket address to connect to.
    /// * `extension` - Extensions used to assign an IP address from the CIDR.
    ///
    /// # Returns
    ///
    /// * `std::io::Result<TcpStream>` - The established TCP connection, or an
    ///   error if the connection failed.
    ///
    /// # Example
    ///
    /// ```
    /// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
    /// let extension = Extensions::new();
    /// let stream = try_connect(addr, extension).await.unwrap();
    /// ```
    pub async fn try_connect(
        &self,
        addr: SocketAddr,
        extension: Extensions,
    ) -> std::io::Result<TcpStream> {
        let result = match (self.cidr, self.fallback) {
            (Some(cidr), None) => {
                timeout(
                    self.connect_timeout,
                    try_connect_with_cidr(addr, cidr, extension),
                )
                .await
            }
            (None, Some(fallback)) => {
                timeout(
                    self.connect_timeout,
                    try_connect_with_fallback(addr, fallback),
                )
                .await
            }
            (Some(cidr), Some(fallback)) => {
                timeout(
                    self.connect_timeout,
                    try_connect_with_cidr_and_fallback(addr, cidr, fallback, extension),
                )
                .await
            }
            (None, None) => timeout(self.connect_timeout, TcpStream::connect(addr)).await,
        }?;

        result
            .and_then(|stream| {
                tracing::info!("connect {} via {}", addr, stream.local_addr()?);
                Ok(stream)
            })
            .map_err(|e| {
                tracing::error!("failed to connect {}: {}", addr, e);
                e
            })
    }
}

/// Tries to establish a TCP connection to the target address using a specific
/// CIDR and extensions.
///
/// This function creates and binds a new TCP socket based on the provided CIDR
/// and extensions, and then tries to connect to the target address.
///
/// If the connection fails, the error is returned.
///
/// # Arguments
///
/// * `target_addr` - The target socket address to connect to.
/// * `cidr` - A CIDR block (either IPv4 or IPv6).
/// * `extension` - Extensions used to assign an IP address from the CIDR.
///
/// # Returns
///
/// * `std::io::Result<TcpStream>` - The established TCP connection, or an error
///   if the connection failed.
///
/// # Example
///
/// ```
/// let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
/// let cidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
/// let extension = Extensions::new();
/// let stream = try_connect_with_cidr(target_addr, cidr, extension)
///     .await
///     .unwrap();
/// ```
async fn try_connect_with_cidr(
    target_addr: SocketAddr,
    cidr: IpCidr,
    extension: Extensions,
) -> std::io::Result<TcpStream> {
    let socket = create_and_bind_socket(cidr, extension).await?;
    socket.connect(target_addr).await
}

/// Tries to establish a TCP connection to the target address using a fallback
/// IP address.
///
/// This function creates a new TCP socket suitable for the fallback IP address,
/// binds the socket to the fallback IP address, and then tries to connect to
/// the target address.
///
/// If the connection fails, the error is returned.
///
/// # Arguments
///
/// * `target_addr` - The target socket address to connect to.
/// * `fallback` - The fallback IP address to use for the connection.
///
/// # Returns
///
/// * `std::io::Result<TcpStream>` - The established TCP connection, or an error
///   if the connection failed.
///
/// # Example
///
/// ```
/// let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
/// let fallback = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// let stream = try_connect_with_fallback(target_addr, fallback)
///     .await
///     .unwrap();
/// ```
async fn try_connect_with_fallback(
    target_addr: SocketAddr,
    fallback: IpAddr,
) -> std::io::Result<TcpStream> {
    let socket = create_tcp_socket_for_ip(&fallback)?;
    let bind_addr = SocketAddr::new(fallback, 0);
    socket.bind(bind_addr)?;
    socket.connect(target_addr).await
}

/// Tries to establish a TCP connection to the target address using a specific
/// CIDR and extensions, with a fallback IP address.
///
/// This function creates and binds a new TCP socket based on the provided CIDR
/// and extensions, and then tries to connect to the target address.
///
/// If the connection fails, it creates a new TCP socket suitable for the
/// fallback IP address, binds the socket to the fallback IP address, and then
/// tries to connect to the target address again.
///
/// # Arguments
///
/// * `target_addr` - The target socket address to connect to.
/// * `cidr` - A CIDR block (either IPv4 or IPv6).
/// * `fallback` - The fallback IP address to use if the connection fails.
/// * `extension` - Extensions used to assign an IP address from the CIDR.
///
/// # Returns
///
/// * `std::io::Result<TcpStream>` - The established TCP connection, or an error
///   if the connection failed.
///
/// # Example
///
/// ```
/// let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
/// let cidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
/// let fallback = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// let extension = Extensions::new();
/// let stream = try_connect_with_cidr_and_fallback(target_addr, cidr, fallback, extension)
///     .await
///     .unwrap();
/// ```
async fn try_connect_with_cidr_and_fallback(
    target_addr: SocketAddr,
    cidr: IpCidr,
    fallback: IpAddr,
    extension: Extensions,
) -> std::io::Result<TcpStream> {
    let socket = create_and_bind_socket(cidr, extension).await?;
    // Try to connect with ipv6
    match socket.connect(target_addr).await {
        Ok(first) => Ok(first),
        Err(err) => {
            tracing::debug!("try connect with ipv6 failed: {}", err);
            // Try to connect with fallback ip (ipv4 or ipv6)
            let socket = create_tcp_socket_for_ip(&fallback)?;
            let bind_addr = SocketAddr::new(fallback, 0);
            socket.bind(bind_addr)?;
            socket.connect(target_addr).await
        }
    }
}

/// Creates and binds a new TCP socket based on the provided CIDR and
/// extensions.
///
/// This function first determines whether the CIDR is IPv4 or IPv6.
/// Then, it creates a new TCP socket of the appropriate type.
/// It assigns an IP address from the CIDR using the provided extensions,
/// and binds the socket to this IP address.
///
/// # Arguments
///
/// * `cidr` - A CIDR block (either IPv4 or IPv6).
/// * `extension` - Extensions used to assign an IP address from the CIDR.
///
/// # Returns
///
/// * `std::io::Result<(IpAddr, TcpSocket)>` - A tuple containing the assigned
///   IP address and the new, bound TCP socket.
///
/// # Example
///
/// ```
/// let cidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
/// let extension = Extensions::new();
/// let (ip, socket) = create_and_bind_socket(cidr, extension).await.unwrap();
/// ```
async fn create_and_bind_socket(cidr: IpCidr, extension: Extensions) -> std::io::Result<TcpSocket> {
    match cidr {
        IpCidr::V4(cidr) => {
            let socket = TcpSocket::new_v4()?;
            let bind = IpAddr::V4(assign_ipv4_from_extension(&cidr, extension));
            socket.bind(SocketAddr::new(bind, 0))?;
            Ok(socket)
        }
        IpCidr::V6(cidr) => {
            let socket = TcpSocket::new_v6()?;
            let bind = IpAddr::V6(assign_ipv6_from_extension(&cidr, extension));
            socket.bind(SocketAddr::new(bind, 0))?;
            Ok(socket)
        }
    }
}

/// Creates a new TCP socket suitable for the provided IP address.
/// If the IP address is IPv4, it creates a new IPv4 socket.
/// If the IP address is IPv6, it creates a new IPv6 socket.
///
/// # Arguments
///
/// * `ip` - An IP address (either IPv4 or IPv6).
///
/// # Returns
///
/// * `std::io::Result<TcpSocket>` - A new TCP socket suitable for the provided
///   IP address.
///
/// # Example
///
/// ```
/// let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
/// let socket = create_tcp_socket_for_ip(ip);
/// ```
fn create_tcp_socket_for_ip(ip: &IpAddr) -> std::io::Result<TcpSocket> {
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
fn assign_ipv4_from_extension(cidr: &Ipv4Cidr, extension: Extensions) -> Ipv4Addr {
    match extension {
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
fn assign_ipv6_from_extension(cidr: &Ipv6Cidr, extension: Extensions) -> Ipv6Addr {
    match extension {
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
            result.push(assign_ipv6_from_extension(&cidr, x.clone()));
        }

        let mut check = Vec::new();
        for x in &mut sessions {
            check.push(assign_ipv6_from_extension(&cidr, x.clone()));
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
            result.push(assign_ipv4_from_extension(&cidr, x.clone()));
        }

        let mut check = Vec::new();
        for x in &mut sessions {
            check.push(assign_ipv4_from_extension(&cidr, x.clone()));
        }

        for x in &result {
            assert!(check.contains(x), "IP {} not found in check", x);
        }
    }
}
