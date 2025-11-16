use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
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
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};

use super::{ext::Extension, rand};

/// Represents a fallback option for outbound connections.
#[derive(Clone)]
pub enum Fallback {
    Address(IpAddr),
    #[cfg(unix)]
    Interface(String),
}

/// Represents a target address for outbound connections.
#[non_exhaustive]
pub enum TargetAddr {
    SocketAddress(SocketAddr),
    DomainAddress(String, u16),
    Authority(Authority),
}

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
    fallback: Option<Fallback>,

    /// Connect timeout in milliseconds.
    connect_timeout: Duration,

    /// Enable SO_REUSEADDR for outbond connection socket
    reuseaddr: Option<bool>,

    /// Default http connector
    http: connect::HttpConnector,
}

/// `TcpConnector` is a lightweight wrapper for TCP connection settings.
/// It provides methods to create and manage TCP connections using the configuration from
/// `Connector`.
pub struct TcpConnector<'a> {
    inner: &'a Connector,
    extension: Extension,
}

/// `UdpConnector` is a lightweight wrapper for UDP connection settings.
/// It provides methods to create and manage UDP sockets using the configuration from `Connector`.
pub struct UdpConnector<'a> {
    inner: &'a Connector,
    extension: Extension,
}

/// `HttpConnector` is a lightweight wrapper for HTTP connection settings.
/// It provides methods to create and manage HTTP connections using the configuration from
/// `Connector`.
pub struct HttpConnector<'a> {
    inner: &'a Connector,
    extension: Extension,
}

// ==== impl Fallback ====

impl FromStr for Fallback {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<IpAddr>() {
            Ok(addr) => Ok(Fallback::Address(addr)),
            #[cfg(unix)]
            Err(_) => Ok(Fallback::Interface(s.to_owned())),
            #[cfg(not(unix))]
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid fallback address: {err}"),
            )),
        }
    }
}

// ==== impl TargetAddr ====

impl From<SocketAddr> for TargetAddr {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        TargetAddr::SocketAddress(addr)
    }
}

impl From<(String, u16)> for TargetAddr {
    #[inline]
    fn from(addr: (String, u16)) -> Self {
        TargetAddr::DomainAddress(addr.0, addr.1)
    }
}

impl From<Authority> for TargetAddr {
    #[inline]
    fn from(addr: Authority) -> Self {
        TargetAddr::Authority(addr)
    }
}

// ==== impl Connector ====

impl Connector {
    /// Constructs a new [`Connector`] instance, accepting optional IPv6 CIDR and
    /// fallback IP address as parameters.
    pub(super) fn new(
        cidr: Option<IpCidr>,
        cidr_range: Option<u8>,
        fallback: Option<Fallback>,
        connect_timeout: u64,
        reuseaddr: Option<bool>,
    ) -> Self {
        let connect_timeout = Duration::from_secs(connect_timeout);
        let mut http_connector = connect::HttpConnector::new();
        http_connector.set_connect_timeout(Some(connect_timeout));
        if let Some(reuseaddr) = reuseaddr {
            http_connector.set_reuse_address(reuseaddr);
        }
        Connector {
            cidr,
            cidr_range,
            fallback,
            connect_timeout,
            http: http_connector,
            reuseaddr,
        }
    }

    /// Creates a new [`HttpConnector`] instance.
    #[inline]
    pub fn http(&self, extension: Extension) -> HttpConnector<'_> {
        HttpConnector {
            inner: self,
            extension,
        }
    }

    /// Creates a new [`TcpConnector`] instance.
    #[inline]
    pub fn tcp(&self, extension: Extension) -> TcpConnector<'_> {
        TcpConnector {
            inner: self,
            extension,
        }
    }

    /// Creates a new [`UdpConnector`] instance.
    #[inline]
    pub fn udp(&self, extension: Extension) -> UdpConnector<'_> {
        UdpConnector {
            inner: self,
            extension,
        }
    }
}

// ==== impl TcpConnector ====

impl TcpConnector<'_> {
    /// Returns a SocketAddr for binding (port 0). Uses CIDR, fallback IP, or default function.
    pub fn socket_addr<F>(&self, default: F) -> std::io::Result<SocketAddr>
    where
        F: FnOnce() -> std::io::Result<IpAddr>,
    {
        match (self.inner.cidr, &self.inner.fallback) {
            (Some(IpCidr::V4(cidr)), _) => {
                let addr = assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension);
                Ok(SocketAddr::new(IpAddr::V4(addr), 0))
            }
            (Some(IpCidr::V6(cidr)), _) => {
                let addr = assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension);
                Ok(SocketAddr::new(IpAddr::V6(addr), 0))
            }
            (None, Some(Fallback::Address(addr))) => Ok(SocketAddr::new(*addr, 0)),
            _ => default().map(|ip| SocketAddr::new(ip, 0)),
        }
    }

    /// Creates a [`TcpSocket`] and binds it to an IP address within the provided CIDR range.
    async fn create_socket_with_cidr(&self, cidr: IpCidr) -> std::io::Result<TcpSocket> {
        match cidr {
            IpCidr::V4(cidr) => {
                let socket = TcpSocket::new_v4()?;
                let addr = assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension);
                socket.bind(SocketAddr::new(IpAddr::V4(addr), 0))?;
                Ok(socket)
            }
            IpCidr::V6(cidr) => {
                let socket = TcpSocket::new_v6()?;
                let addr = assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension);
                socket.bind(SocketAddr::new(IpAddr::V6(addr), 0))?;
                Ok(socket)
            }
        }
    }

    /// Creates a [`TcpSocket`] and binds it to the fallback address.
    fn create_socket_with_fallback(
        &self,
        #[cfg_attr(not(unix), allow(unused))] target_addr: SocketAddr,
        fallback: &Fallback,
    ) -> std::io::Result<TcpSocket> {
        let socket = match fallback {
            Fallback::Address(IpAddr::V4(addr)) => {
                let socket = TcpSocket::new_v4()?;
                let bind_addr = SocketAddr::new(IpAddr::V4(*addr), 0);
                socket.bind(bind_addr)?;
                socket
            }
            Fallback::Address(IpAddr::V6(addr)) => {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = SocketAddr::new(IpAddr::V6(*addr), 0);
                socket.bind(bind_addr)?;
                socket
            }
            #[cfg(unix)]
            Fallback::Interface(interface) => {
                let socket = match target_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };
                let socket_ref = socket2::SockRef::from(&socket);

                // On Linux-like systems, set the interface to bind using
                // `SO_BINDTODEVICE`.
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                socket_ref.bind_device(Some(interface.as_bytes()))?;

                // On macOS-like and Solaris-like systems, we instead use `IP_BOUND_IF`.
                // This socket option desires an integer index for the interface, so we
                // must first determine the index of the requested interface name using
                // `if_nametoindex`.
                #[cfg(any(
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos",
                ))]
                {
                    let interface = std::ffi::CString::new(interface.as_str())?;
                    #[allow(unsafe_code)]
                    let idx = unsafe { nix::libc::if_nametoindex(interface.as_ptr()) };
                    let idx = std::num::NonZeroU32::new(idx).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Interface {interface:?} not found"),
                        )
                    })?;

                    // Different setsockopt calls are necessary depending on whether the
                    // address is IPv4 or IPv6.
                    match target_addr {
                        SocketAddr::V4(_) => socket_ref.bind_device_by_index_v4(Some(idx)),
                        SocketAddr::V6(_) => socket_ref.bind_device_by_index_v6(Some(idx)),
                    }?;
                }

                socket
            }
        };

        socket.set_nodelay(true)?;
        if let Some(reuseaddr) = self.inner.reuseaddr {
            socket.set_reuseaddr(reuseaddr)?;
        }

        Ok(socket)
    }

    // Attempts to establish a TCP connection to the target address using the
    // provided IP address.
    async fn connect_with_fallback(
        &self,
        target_addr: SocketAddr,
        fallback: &Fallback,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_with_fallback(target_addr, fallback)?;
        socket.connect(target_addr).await
    }

    /// Attempts to establish a TCP connection to the target address using an IP
    /// address from the provided CIDR range.
    async fn connect_with_cidr(
        &self,
        target_addr: SocketAddr,
        cidr: IpCidr,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_with_cidr(cidr).await?;
        socket.connect(target_addr).await
    }

    /// Attempts to establish a TCP connection to the target address using an IP
    /// address from the provided CIDR range. If the connection attempt fails, it
    /// falls back to using the provided fallback IP address.
    async fn connect_with_cidr_fallback(
        &self,
        target_addr: SocketAddr,
        cidr: IpCidr,
        fallback: &Fallback,
    ) -> std::io::Result<TcpStream> {
        let preferred_fut = self.connect_with_cidr(target_addr, cidr);
        futures_util::pin_mut!(preferred_fut);

        let fallback_fut = self.connect_with_fallback(target_addr, fallback);
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

    /// Attempts to establish a TCP connection to each of the target addresses
    /// in the provided iterator using the provided extensions.
    async fn connect_with_addrs(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> std::io::Result<TcpStream> {
        let mut last_err = None;
        for target_addr in addrs {
            let res = match (self.inner.cidr, &self.inner.fallback) {
                (None, Some(fallback)) => {
                    timeout(
                        self.inner.connect_timeout,
                        self.connect_with_fallback(target_addr, fallback),
                    )
                    .await?
                }
                (Some(cidr), None) => {
                    timeout(
                        self.inner.connect_timeout,
                        self.connect_with_cidr(target_addr, cidr),
                    )
                    .await?
                }
                (Some(cidr), Some(fallback)) => {
                    timeout(
                        self.inner.connect_timeout,
                        self.connect_with_cidr_fallback(target_addr, cidr, fallback),
                    )
                    .await?
                }
                (None, None) => {
                    timeout(self.inner.connect_timeout, TcpStream::connect(target_addr)).await?
                }
            }
            .and_then(|stream| {
                tracing::info!("[TCP] connect {} via {}", target_addr, stream.local_addr()?);
                Ok(stream)
            });

            match res {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(error(last_err))
    }

    /// Attempts to establish a TCP connection to the given target address.
    ///
    /// This method supports three types of target addresses:
    /// - `SocketAddress`: Connects directly to the specified IP and port.
    /// - `DomainAddress`: Resolves the domain to one or more IP addresses and tries each in order.
    /// - `Authority`: Resolves the authority (host[:port]) and tries each resolved address.
    ///
    /// The connection will use the configured CIDR, fallback IP, and connection timeout as needed.
    /// If multiple addresses are resolved, it will attempt each until one succeeds or all fail.
    pub async fn connect<T: Into<TargetAddr>>(&self, target_addr: T) -> std::io::Result<TcpStream> {
        match target_addr.into() {
            TargetAddr::SocketAddress(addr) => {
                let addrs = std::iter::once(addr);
                self.connect_with_addrs(addrs).await
            }
            TargetAddr::DomainAddress(domain, port) => {
                let addrs = lookup_host((domain, port)).await?;
                self.connect_with_addrs(addrs).await
            }
            TargetAddr::Authority(authority) => {
                let addrs = lookup_host(authority.as_str()).await?;
                self.connect_with_addrs(addrs).await
            }
        }
    }
}

// ==== impl UdpConnector ====

impl UdpConnector<'_> {
    /// Creates a [`UdpSocket`] and binds it to the provided IP address.
    #[inline]
    async fn create_socket(&self, ip: IpAddr) -> std::io::Result<UdpSocket> {
        UdpSocket::bind(SocketAddr::new(ip, 0)).await
    }

    /// Creates a [`UdpSocket`] and binds it to an IP address within the provided CIDR range.
    async fn create_socket_with_cidr(&self, cidr: IpCidr) -> std::io::Result<UdpSocket> {
        match cidr {
            IpCidr::V4(cidr) => {
                let addr = assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension);
                UdpSocket::bind(SocketAddr::new(IpAddr::V4(addr), 0)).await
            }
            IpCidr::V6(cidr) => {
                let addr = assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension);
                UdpSocket::bind(SocketAddr::new(IpAddr::V6(addr), 0)).await
            }
        }
    }

    /// Binds UDP sockets based on the configured CIDR and fallback IP address.
    /// If both CIDR and fallback are provided and belong to different IP families,
    /// it creates two sockets for dual-stack support. Otherwise, it creates a single
    /// socket based on the available configuration.
    pub async fn create_socket_dual_stack(
        &self,
    ) -> std::io::Result<(UdpSocket, Option<UdpSocket>)> {
        match (self.inner.cidr, &self.inner.fallback) {
            (Some(cidr), Some(Fallback::Address(addr))) => {
                // Different IP families - create dual-stack sockets
                let preferred_socket = self.create_socket_with_cidr(cidr).await?;
                let fallback_socket = self.create_socket(*addr).await?;
                Ok((preferred_socket, Some(fallback_socket)))
            }
            (None, Some(Fallback::Address(addr))) => {
                let fallback_socket = self.create_socket(*addr).await?;
                Ok((fallback_socket, None))
            }
            (Some(cidr), None) => {
                let fallback_socket = self.create_socket_with_cidr(cidr).await?;
                Ok((fallback_socket, None))
            }
            _ => {
                // Create dual-stack sockets when no specific configuration is provided
                let preferred_socket = UdpSocket::bind("0.0.0.0:0").await?;
                let fallback_socket = UdpSocket::bind("[::]:0").await;
                Ok((preferred_socket, fallback_socket.ok()))
            }
        }
    }

    /// Sends a UDP packet to a single target address using the provided UDP sockets.
    /// It tries preferred socket first, then falls back to fallback socket with delay if needed.
    async fn send_packet_with_addr(
        &self,
        pkt: &[u8],
        addr: SocketAddr,
        preferred_outbound: &UdpSocket,
        fallback_outbound: Option<&UdpSocket>,
    ) -> std::io::Result<usize> {
        let preferred_fut = self.try_send_to_addr(pkt, addr, preferred_outbound);
        futures_util::pin_mut!(preferred_fut);

        // If we have a fallback socket, prepare the fallback future
        if let Some(fallback_socket) = fallback_outbound {
            let fallback_fut = self.try_send_to_addr(pkt, addr, fallback_socket);
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
                        Either::Left((result, fallback_fut)) => {
                            (result, Either::Right(fallback_fut))
                        }
                        Either::Right((result, preferred_fut)) => {
                            (result, Either::Left(preferred_fut))
                        }
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
        } else {
            // No fallback socket available, just use preferred
            preferred_fut.await
        }
    }

    /// Sends a UDP packet to multiple target addresses using the provided UDP sockets.
    /// Tries each address in order until one succeeds or all fail.
    async fn send_packet_with_addrs(
        &self,
        pkt: &[u8],
        addrs: impl IntoIterator<Item = SocketAddr>,
        preferred_outbound: &UdpSocket,
        fallback_outbound: Option<&UdpSocket>,
    ) -> std::io::Result<usize> {
        let mut last_err = None;

        for addr in addrs {
            match self
                .send_packet_with_addr(pkt, addr, preferred_outbound, fallback_outbound)
                .await
            {
                Ok(size) => return Ok(size),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(error(last_err))
    }

    /// Helper method to try sending UDP packet to a single address using a single socket
    async fn try_send_to_addr(
        &self,
        pkt: &[u8],
        addr: SocketAddr,
        socket: &UdpSocket,
    ) -> std::io::Result<usize> {
        socket.send_to(pkt, addr).await.and_then(|size| {
            tracing::info!(
                "[UDP] UDP packet sent to {} via {}, size: {}",
                addr,
                socket.local_addr()?,
                size
            );

            Ok(size)
        })
    }

    /// Sends a UDP packet to the specified target address using dual-stack UDP sockets.
    pub async fn send_packet<T: Into<TargetAddr>>(
        &self,
        pkt: &[u8],
        target_addr: T,
        preferred_outbound: &UdpSocket,
        fallback_outbound: Option<&UdpSocket>,
    ) -> std::io::Result<usize> {
        match target_addr.into() {
            TargetAddr::SocketAddress(addr) => {
                timeout(
                    self.inner.connect_timeout,
                    self.send_packet_with_addr(pkt, addr, preferred_outbound, fallback_outbound),
                )
                .await?
            }
            TargetAddr::DomainAddress(domain, port) => {
                let addrs = lookup_host((domain, port)).await?;
                timeout(
                    self.inner.connect_timeout,
                    self.send_packet_with_addrs(pkt, addrs, preferred_outbound, fallback_outbound),
                )
                .await?
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Authority is not supported for UDP",
            )),
        }
    }
}

// ==== impl HttpConnector ====

impl HttpConnector<'_> {
    /// Sends an HTTP request using the configured `HttpConnector`.
    pub async fn send_request(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        let mut connector = self.inner.http.clone();
        match (self.inner.cidr, &self.inner.fallback) {
            (Some(cidr), Some(fallback)) => match (cidr, fallback) {
                (IpCidr::V4(cidr), Fallback::Address(IpAddr::V6(v6))) => {
                    let v4 =
                        assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension);
                    connector.set_local_addresses(v4, *v6);
                }
                (IpCidr::V6(cidr), Fallback::Address(IpAddr::V4(v4))) => {
                    let v6 =
                        assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension);
                    connector.set_local_addresses(*v4, v6);
                }
                #[cfg(unix)]
                (_, Fallback::Interface(iface)) => {
                    connector.set_interface(iface);
                }
                _ => {}
            },
            (Some(cidr), None) => match cidr {
                IpCidr::V4(ipv4_cidr) => {
                    let addr = assign_ipv4_from_extension(
                        ipv4_cidr,
                        self.inner.cidr_range,
                        self.extension,
                    );
                    connector.set_local_address(Some(addr.into()));
                }
                IpCidr::V6(ipv6_cidr) => {
                    let addr = assign_ipv6_from_extension(
                        ipv6_cidr,
                        self.inner.cidr_range,
                        self.extension,
                    );
                    connector.set_local_address(Some(addr.into()));
                }
            },
            (None, Some(fallback)) => match fallback {
                Fallback::Address(addr) => connector.set_local_address(Some(*addr)),
                #[cfg(unix)]
                Fallback::Interface(iface) => {
                    connector.set_interface(iface);
                }
            },
            _ => {}
        }

        connector.set_nodelay(true);
        if let Some(reuseaddr) = self.inner.reuseaddr {
            connector.set_reuse_address(reuseaddr);
        }

        Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(connector)
            .request(req)
            .await
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
                let network_length = cidr.network_length();
                if u32::from(network_length) >= Ipv4Addr::BITS {
                    return cidr.first_address();
                }

                // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
                // the non-variable part
                let subnet_mask = !((1u32 << (32 - network_length)) - 1);
                let base_ip_bits = u32::from(cidr.first_address()) & subnet_mask;
                let capacity = 2u32.pow(32 - network_length as u32) - 1;
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
                if u32::from(network_length) >= Ipv6Addr::BITS {
                    return cidr.first_address();
                }

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
    let rand: u32 = rand::random_u32();
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
    let rand: u128 = rand::random_u128();
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
    let host_part: u32 = rand::random_u32() & host_mask;

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
    let host_part: u128 = (rand::random_u64() as u128) & host_mask;

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

    #[test]
    fn test_assign_ip_from_extension_with_full_cidr() {
        let cidr_v4 = "192.168.0.1/32".parse::<Ipv4Cidr>().unwrap();
        let extension = Extension::Session(0x12345);
        let ipv4_address = assign_ipv4_from_extension(cidr_v4, None, extension);
        assert_eq!(ipv4_address, "192.168.0.1".parse::<Ipv4Addr>().unwrap());

        let cidr_v6 = "2001:db8::1/128".parse::<Ipv6Cidr>().unwrap();
        let ipv6_address = assign_ipv6_from_extension(cidr_v6, None, extension);
        assert_eq!(ipv6_address, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }
}
