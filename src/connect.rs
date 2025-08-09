use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use futures_util::future::Either;
use http::{Request, Response, uri::Authority};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{Client, connect},
    rt::{TokioExecutor, TokioTimer},
};
use rand::random;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};

use super::{extension::Extension, http::error::Error};

/// `Connector` struct is used to create HTTP connectors, optionally configured
/// with an IPv6 CIDR and a fallback IP address.
#[derive(Clone)]
pub struct Connector {
    /// Optional IPv6 CIDR (Classless Inter-Domain Routing), used to optionally
    /// configure an IPv6 address.
    cidr: Option<IpCidr>,

    /// Optional CIDR range for IP addresses.
    cidr_range: Option<u8>,

    /// Optional IP address as a fallback option in case of connection failure.
    fallback: Option<IpAddr>,

    /// Connect timeout in milliseconds.
    connect_timeout: Duration,

    /// Default http connector
    http: connect::HttpConnector,
}

/// `TcpConnector` is a lightweight wrapper for TCP connection settings.
/// It provides methods to create and manage TCP connections using the configuration from
/// `Connector`.
pub struct TcpConnector<'a> {
    inner: &'a Connector,
}

/// `UdpConnector` is a lightweight wrapper for UDP connection settings.
/// It provides methods to create and manage UDP sockets using the configuration from `Connector`.
pub struct UdpConnector<'a> {
    inner: &'a Connector,
}

/// `HttpConnector` is a lightweight wrapper for HTTP connection settings.
/// It provides methods to create and manage HTTP connections using the configuration from
/// `Connector`.
pub struct HttpConnector<'a> {
    inner: &'a Connector,
}

// ==== impl Connector ====

impl Connector {
    /// Constructs a new [`Connector`] instance, accepting optional IPv6 CIDR and
    /// fallback IP address as parameters.
    pub(super) fn new(
        cidr: Option<IpCidr>,
        cidr_range: Option<u8>,
        fallback: Option<IpAddr>,
        connect_timeout: u64,
    ) -> Self {
        let connect_timeout = Duration::from_secs(connect_timeout);
        let mut http_connector = connect::HttpConnector::new();
        http_connector.set_connect_timeout(Some(connect_timeout));
        Connector {
            cidr,
            cidr_range,
            fallback,
            connect_timeout,
            http: http_connector,
        }
    }

    /// Creates a new [`HttpConnector`] using the current configuration.
    #[inline]
    pub fn http_connector(&self) -> HttpConnector<'_> {
        HttpConnector { inner: self }
    }

    /// Creates a new [`TcpConnector`] using the current configuration.
    #[inline]
    pub fn tcp_connector(&self) -> TcpConnector<'_> {
        TcpConnector { inner: self }
    }

    /// Creates a new [`UdpConnector`] using the current configuration.
    #[inline]
    pub fn udp_connector(&self) -> UdpConnector<'_> {
        UdpConnector { inner: self }
    }
}

// ==== impl TcpConnector ====

impl TcpConnector<'_> {
    /// Binds a socket to an IP address based on the provided CIDR, fallback IP, and extensions.
    pub fn bind_socket_addr<F>(
        &self,
        default: F,
        extension: Extension,
    ) -> std::io::Result<SocketAddr>
    where
        F: FnOnce() -> std::io::Result<IpAddr>,
    {
        match (self.inner.cidr, self.inner.fallback) {
            (Some(cidr), _) => match cidr {
                IpCidr::V4(cidr) => {
                    let ip = IpAddr::V4(assign_ipv4_from_extension(
                        cidr,
                        self.inner.cidr_range,
                        extension,
                    ));
                    Ok(SocketAddr::new(ip, 0))
                }
                IpCidr::V6(cidr) => {
                    let ip = IpAddr::V6(assign_ipv6_from_extension(
                        cidr,
                        self.inner.cidr_range,
                        extension,
                    ));
                    Ok(SocketAddr::new(ip, 0))
                }
            },
            (None, Some(fallback)) => Ok(SocketAddr::new(fallback, 0)),
            _ => default().map(|ip| SocketAddr::new(ip, 0)),
        }
    }

    /// Attempts to establish a TCP connection to each of the target addresses
    /// in the provided iterator using the provided extensions.
    pub async fn connect_with_addrs(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        let mut last_err = None;

        for target_addr in addrs {
            match self.connect(target_addr, extension).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            };
        }

        Err(error(last_err))
    }

    /// Attempts to establish a TCP connection to each of the target addresses
    /// resolved from the provided authority.
    #[inline]
    pub async fn connect_with_authority(
        &self,
        authority: Authority,
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        let addrs = lookup_host(authority.as_str()).await?;
        self.connect_with_addrs(addrs, extension).await
    }

    /// Attempts to establish a TCP connection to the target domain using the
    /// provided extensions.
    #[inline]
    pub async fn connect_with_domain(
        &self,
        host: (String, u16),
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        let addrs = lookup_host(host).await?;
        self.connect_with_addrs(addrs, extension).await
    }

    /// Attempts to establish a TCP connection to the target address using the
    /// provided extensions, CIDR range, and fallback IP address.
    pub async fn connect(
        &self,
        target_addr: SocketAddr,
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        match (self.inner.cidr, self.inner.fallback) {
            (None, Some(fallback)) => {
                timeout(
                    self.inner.connect_timeout,
                    self.connect_with_addr(target_addr, fallback),
                )
                .await?
            }
            (Some(cidr), None) => {
                timeout(
                    self.inner.connect_timeout,
                    self.connect_with_cidr(target_addr, cidr, extension),
                )
                .await?
            }
            (Some(cidr), Some(fallback)) => {
                timeout(
                    self.inner.connect_timeout,
                    self.connect_with_cidr_and_fallback(target_addr, cidr, fallback, extension),
                )
                .await?
            }
            (None, None) => {
                timeout(self.inner.connect_timeout, TcpStream::connect(target_addr)).await?
            }
        }
        .and_then(|stream| {
            tracing::info!("connect {} via {}", target_addr, stream.local_addr()?);
            Ok(stream)
        })
    }

    /// Attempts to establish a TCP connection to the target address using an IP
    /// address from the provided CIDR range.
    #[inline]
    async fn connect_with_cidr(
        &self,
        target_addr: SocketAddr,
        cidr: IpCidr,
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_with_cidr(cidr, extension).await?;
        socket.connect(target_addr).await
    }

    /// Attempts to establish a TCP connection to the target address using the
    /// provided fallback IP address.
    #[inline]
    async fn connect_with_addr(
        &self,
        target_addr: SocketAddr,
        fallback: IpAddr,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_with_addr(fallback)?;
        socket.connect(target_addr).await
    }

    /// Attempts to establish a TCP connection to the target address using an IP
    /// address from the provided CIDR range. If the connection attempt fails, it
    /// falls back to using the provided fallback IP address.
    async fn connect_with_cidr_and_fallback(
        &self,
        target_addr: SocketAddr,
        cidr: IpCidr,
        fallback: IpAddr,
        extension: Extension,
    ) -> std::io::Result<TcpStream> {
        let preferred_fut = self.connect_with_cidr(target_addr, cidr, extension);
        futures_util::pin_mut!(preferred_fut);

        let fallback_fut = self.connect_with_addr(target_addr, fallback);
        futures_util::pin_mut!(fallback_fut);

        let fallback_delay = tokio::time::sleep(self.inner.connect_timeout);
        futures_util::pin_mut!(fallback_delay);

        let (result, future) = match futures_util::future::select(preferred_fut, fallback_delay)
            .await
        {
            Either::Left((result, _fallback_delay)) => (result, Either::Right(fallback_fut)),
            Either::Right(((), preferred_fut)) => {
                // Delay is done, start polling both the preferred and the fallback
                match futures_util::future::select(preferred_fut, fallback_fut).await {
                    Either::Left((result, fallback_fut)) => (result, Either::Right(fallback_fut)),
                    Either::Right((result, preferred_fut)) => (result, Either::Left(preferred_fut)),
                }
            }
        };

        if result.is_err() {
            // Fallback to the remaining future (could be preferred or fallback)
            // if we get an error
            future.await
        } else {
            result
        }
    }

    /// Creates a TCP socket and binds it to the provided IP address.
    fn create_socket_with_addr(&self, ip: IpAddr) -> std::io::Result<TcpSocket> {
        match ip {
            IpAddr::V4(_) => {
                let socket = TcpSocket::new_v4()?;
                let bind_addr = SocketAddr::new(ip, 0);
                socket.bind(bind_addr)?;
                Ok(socket)
            }
            IpAddr::V6(_) => {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = SocketAddr::new(ip, 0);
                socket.bind(bind_addr)?;
                Ok(socket)
            }
        }
    }

    /// Creates a TCP socket and binds it to an IP address within the provided CIDR range.
    async fn create_socket_with_cidr(
        &self,
        cidr: IpCidr,
        extension: Extension,
    ) -> std::io::Result<TcpSocket> {
        match cidr {
            IpCidr::V4(cidr) => {
                let socket = TcpSocket::new_v4()?;
                let bind = IpAddr::V4(assign_ipv4_from_extension(
                    cidr,
                    self.inner.cidr_range,
                    extension,
                ));
                socket.bind(SocketAddr::new(bind, 0))?;
                Ok(socket)
            }
            IpCidr::V6(cidr) => {
                let socket = TcpSocket::new_v6()?;
                let bind = IpAddr::V6(assign_ipv6_from_extension(
                    cidr,
                    self.inner.cidr_range,
                    extension,
                ));
                socket.bind(SocketAddr::new(bind, 0))?;
                Ok(socket)
            }
        }
    }
}

// ==== impl UdpConnector ====

impl UdpConnector<'_> {
    /// Binds a UDP socket to an IP address based on the provided CIDR, fallback IP, and extensions.
    #[inline]
    pub async fn bind_socket(&self, extension: Extension) -> std::io::Result<UdpSocket> {
        match (self.inner.cidr, self.inner.fallback) {
            (None, Some(fallback)) => self.create_socket_with_addr(fallback).await,
            (Some(cidr), None) => self.create_socket_with_cidr(cidr, extension).await,
            (Some(cidr), Some(fallback)) => {
                self.create_socket_with_cidr_and_fallback(cidr, fallback, extension)
                    .await
            }
            (None, None) => UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await,
        }
    }

    /// Sends a UDP packet to the specified address using the provided UDP socket.
    #[inline]
    pub async fn send_packet_with_addr(
        &self,
        dispatch_socket: &UdpSocket,
        pkt: &[u8],
        dst_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        dispatch_socket.send_to(pkt, dst_addr).await
    }

    /// Sends a UDP packet to the specified domain and port using the provided UDP socket.
    pub async fn send_packet_with_domain(
        &self,
        dispatch_socket: &UdpSocket,
        pkt: &[u8],
        dst_domain: (String, u16),
    ) -> std::io::Result<usize> {
        let mut last_err = None;
        let addrs = lookup_host(dst_domain).await?;
        for addr in addrs {
            match self.send_packet_with_addr(dispatch_socket, pkt, addr).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(error(last_err))
    }

    /// Creates a UDP socket and binds it to the provided IP address.
    #[inline]
    async fn create_socket_with_addr(&self, ip: IpAddr) -> std::io::Result<UdpSocket> {
        UdpSocket::bind(SocketAddr::new(ip, 0)).await
    }

    /// Creates a UDP socket and binds it to an IP address within the provided CIDR range.
    async fn create_socket_with_cidr(
        &self,
        cidr: IpCidr,
        extension: Extension,
    ) -> std::io::Result<UdpSocket> {
        match cidr {
            IpCidr::V4(cidr) => {
                let bind = IpAddr::V4(assign_ipv4_from_extension(
                    cidr,
                    self.inner.cidr_range,
                    extension,
                ));
                UdpSocket::bind(SocketAddr::new(bind, 0)).await
            }
            IpCidr::V6(cidr) => {
                let bind = IpAddr::V6(assign_ipv6_from_extension(
                    cidr,
                    self.inner.cidr_range,
                    extension,
                ));
                UdpSocket::bind(SocketAddr::new(bind, 0)).await
            }
        }
    }

    /// Creates a UDP socket and binds it to an IP address within the provided CIDR
    /// range. If the binding fails, it falls back to using the provided fallback IP
    /// address.
    async fn create_socket_with_cidr_and_fallback(
        &self,
        cidr: IpCidr,
        fallback: IpAddr,
        extension: Extension,
    ) -> std::io::Result<UdpSocket> {
        match self.create_socket_with_cidr(cidr, extension).await {
            Ok(first) => Ok(first),
            Err(err) => {
                tracing::debug!("create socket with cidr failed: {}", err);
                self.create_socket_with_addr(fallback).await
            }
        }
    }
}

// ==== impl HttpConnector ====

impl HttpConnector<'_> {
    /// Sends an HTTP request using the configured `HttpConnector`.
    pub async fn send_request(
        self,
        req: Request<Incoming>,
        extension: Extension,
    ) -> Result<Response<Incoming>, Error> {
        let mut connector = self.inner.http.clone();
        match (self.inner.cidr, self.inner.fallback) {
            (Some(IpCidr::V4(cidr)), Some(IpAddr::V6(v6))) => {
                let v4 = assign_ipv4_from_extension(cidr, self.inner.cidr_range, extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V4(cidr)), None) => {
                let v4 = assign_ipv4_from_extension(cidr, self.inner.cidr_range, extension);
                connector.set_local_address(Some(v4.into()));
            }
            (Some(IpCidr::V6(cidr)), Some(IpAddr::V4(v4))) => {
                let v6 = assign_ipv6_from_extension(cidr, self.inner.cidr_range, extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V6(cidr)), None) => {
                let v6 = assign_ipv6_from_extension(cidr, self.inner.cidr_range, extension);
                connector.set_local_address(Some(v6.into()));
            }
            (None, addr) => connector.set_local_address(addr),
            _ => {}
        }

        Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(connector)
            .request(req)
            .await
            .map_err(Into::into)
    }
}

/// Returns the last error encountered during a series of connection attempts,
/// or a `ConnectionAborted` error if no connection attempts were made.
fn error(last_err: Option<std::io::Error>) -> std::io::Error {
    match last_err {
        Some(e) => {
            tracing::error!("Failed to connect to any resolved address: {}", e);
            e
        }
        None => std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Failed to connect to any resolved address",
        ),
    }
}

/// Assigns an IPv4 address based on the provided CIDR and extension.
/// If the extension is a Session with an ID, the function generates a
/// deterministic IPv4 address within the CIDR range using a murmurhash of the
/// ID. The network part of the address is preserved, and the host part is
/// generated from the hash. If the extension is not a Session, the function
/// generates a random IPv4 address within the CIDR range.
fn assign_ipv4_from_extension(
    cidr: Ipv4Cidr,
    cidr_range: Option<u8>,
    extension: Extension,
) -> Ipv4Addr {
    if let Some(combined) = extract_value_from_extension(extension) {
        match extension {
            Extension::TTL(_) | Extension::Session(_) => {
                // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
                // the non-variable part
                let subnet_mask = !((1u32 << (32 - cidr.network_length())) - 1);
                let base_ip_bits = u32::from(cidr.first_address()) & subnet_mask;
                let capacity = 2u32.pow(32 - cidr.network_length() as u32) - 1;
                let ip_num = base_ip_bits | ((combined as u32) % capacity);
                return Ipv4Addr::from(ip_num);
            }
            Extension::Range(_) => {
                // If a CIDR range is provided, use it to assign an IP address
                if let Some(range) = cidr_range {
                    return assign_ipv4_with_range(cidr, range, combined as u32);
                }
            }
            _ => {}
        }
    }

    assign_rand_ipv4(cidr)
}

/// Assigns an IPv6 address based on the provided CIDR and extension.
/// If the extension is a Session with an ID, the function generates a
/// deterministic IPv6 address within the CIDR range using a murmurhash of the
/// ID. The network part of the address is preserved, and the host part is
/// generated from the hash. If the extension is not a Session, the function
/// generates a random IPv6 address within the CIDR range.
fn assign_ipv6_from_extension(
    cidr: Ipv6Cidr,
    cidr_range: Option<u8>,
    extension: Extension,
) -> Ipv6Addr {
    if let Some(combined) = extract_value_from_extension(extension) {
        match extension {
            Extension::TTL(_) | Extension::Session(_) => {
                let network_length = cidr.network_length();
                // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
                // the non-variable part
                let subnet_mask = !((1u128 << (128 - network_length)) - 1);
                let base_ip_bits = u128::from(cidr.first_address()) & subnet_mask;
                let capacity = 2u128.pow(128 - network_length as u32) - 1;
                let ip_num = base_ip_bits | (combined as u128 % capacity);
                return Ipv6Addr::from(ip_num);
            }
            Extension::Range(_) => {
                // If a range is provided, use it to assign an IP
                if let Some(range) = cidr_range {
                    return assign_ipv6_with_range(cidr, range, combined as u128);
                }
            }
            _ => {}
        }
    }

    assign_rand_ipv6(cidr)
}

/// Generates a random IPv4 address within the specified subnet.
/// The subnet is defined by the initial IPv4 address and the prefix length.
/// The network part of the address is preserved, and the host part is randomly
/// generated.
fn assign_rand_ipv4(cidr: Ipv4Cidr) -> Ipv4Addr {
    let mut ipv4 = u32::from(cidr.first_address());
    let prefix_len = cidr.network_length();
    let rand: u32 = random();
    let net_part = (ipv4 >> (32 - prefix_len)) << (32 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv4 = net_part | host_part;
    ipv4.into()
}

/// Generates a random IPv6 address within the specified subnet.
/// The subnet is defined by the initial IPv6 address and the prefix length.
/// The network part of the address is preserved, and the host part is randomly
/// generated.
fn assign_rand_ipv6(cidr: Ipv6Cidr) -> Ipv6Addr {
    let mut ipv6 = u128::from(cidr.first_address());
    let prefix_len = cidr.network_length();
    let rand: u128 = random();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    ipv6.into()
}

/// Generates an IPv4 address within a specified CIDR range, where the address is
/// influenced by a fixed combined value and a random host part.
fn assign_ipv4_with_range(cidr: Ipv4Cidr, range: u8, combined: u32) -> Ipv4Addr {
    let base_ip: u32 = u32::from(cidr.first_address());
    let prefix_len = cidr.network_length();

    // If the range is less than the prefix length, generate a random IP address.
    if range < prefix_len {
        return assign_rand_ipv4(cidr);
    }

    // Shift the combined value to the left by (32 - range) bits to place it in the correct
    // position.
    let combined_shifted = (combined & ((1u32 << (range - prefix_len)) - 1)) << (32 - range);

    // Create a subnet mask that preserves the fixed network part of the IP address.
    let subnet_mask = !((1u32 << (32 - prefix_len)) - 1);
    let subnet_with_fixed = (base_ip & subnet_mask) | combined_shifted;

    // Generate a mask for the host part and a random host part value.
    let host_mask = (1u32 << (32 - range)) - 1;
    let host_part: u32 = random::<u32>() & host_mask;

    // Combine the fixed subnet part and the random host part to form the final IP address.
    Ipv4Addr::from(subnet_with_fixed | host_part)
}

/// Generates an IPv6 address within a specified CIDR range, where the address is
/// influenced by a fixed combined value and a random host part.
fn assign_ipv6_with_range(cidr: Ipv6Cidr, range: u8, combined: u128) -> Ipv6Addr {
    let base_ip: u128 = cidr.first_address().into();
    let prefix_len = cidr.network_length();

    // If the range is less than the prefix length, generate a random IP address.
    if range < prefix_len {
        return assign_rand_ipv6(cidr);
    }

    // Shift the combined value to the left by (128 - range) bits to place it in the correct
    // position.
    let combined_shifted = (combined & ((1u128 << (range - prefix_len)) - 1)) << (128 - range);

    // Create a subnet mask that preserves the fixed network part of the IP address.
    let subnet_mask = !((1u128 << (128 - prefix_len)) - 1);
    let subnet_with_fixed = (base_ip & subnet_mask) | combined_shifted;

    // Generate a mask for the host part and a random host part value.
    let host_mask = (1u128 << (128 - range)) - 1;
    let host_part: u128 = (random::<u64>() as u128) & host_mask;

    // Combine the fixed subnet part and the random host part to form the final IP address.
    Ipv6Addr::from(subnet_with_fixed | host_part)
}

/// Extracts a value from the given `Extension` enum variant.
///
/// This function takes an `Extension` enum and returns an `Option<u64>` containing the value
/// associated with the `Range`, `Session`, or `TTL` variants. If the `Extension` variant does
/// not contain a value (i.e., it is not one of the aforementioned variants), the function returns
/// `None`.
fn extract_value_from_extension(extension: Extension) -> Option<u64> {
    match extension {
        Extension::Range(value) => Some(value),
        Extension::Session(value) => Some(value),
        Extension::TTL(ttl) => Some(ttl),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_ipv4_with_fixed_combined() {
        let cidr = "192.168.0.0/24".parse::<Ipv4Cidr>().unwrap();
        let range = 28;
        let mut combined = 0x5;

        for i in 0..5 {
            combined += i;

            // Generate two IPv4 addresses with the same combined value
            let ipv4_address1 = assign_ipv4_with_range(cidr, range, combined);
            let ipv4_address2 = assign_ipv4_with_range(cidr, range, combined);

            println!("IPv4 Address 1: {ipv4_address1}");
            println!("IPv4 Address 2: {ipv4_address2}");
        }
    }

    #[test]
    fn test_assign_ipv6_with_fixed_combined() {
        let cidr = "2001:470:e953::/48".parse().unwrap();
        let range = 64;
        let mut combined = 0x12345;

        for i in 0..5 {
            combined += i;
            // Generate two IPv6 addresses with the same combined value
            let ipv6_address1 = assign_ipv6_with_range(cidr, range, combined);
            let ipv6_address2 = assign_ipv6_with_range(cidr, range, combined);

            println!("{ipv6_address1}");
            println!("{ipv6_address2}")
        }
    }

    #[test]
    fn test_assign_ipv4_from_extension() {
        let cidr = "2001:470:e953::/48".parse().unwrap();
        let extension = Extension::Session(0x12345);
        let ipv6_address = assign_ipv6_from_extension(cidr, None, extension);
        assert_eq!(
            ipv6_address,
            std::net::Ipv6Addr::from([0x2001, 0x470, 0xe953, 0, 0, 0, 1, 0x2345])
        );
    }
}
