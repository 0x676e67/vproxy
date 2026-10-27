use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
    time::Duration,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use futures_util::future::Either;
use http::{Request, Response, uri::Authority};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{Client, connect},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};

use super::{
    ebpf,
    ext::{Extension, RouteExtension},
    rand,
};

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
    /// An already authorized exact source, never a client-supplied raw IP. If
    /// present, legacy CIDR/interface/default fallback is completely bypassed.
    source: Option<IpAddr>,
    cidr: Option<IpCidr>,
    cidr_range: Option<u8>,
    fallback: Option<Fallback>,
    connect_timeout: Duration,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    tcp_user_timeout: Option<Duration>,
    reuseaddr: Option<bool>,
    http: connect::HttpConnector,
    /// Shared owner of optional egress attachments. A default config preserves
    /// native sockets and rejects explicit presets instead of partial emulation.
    profile_config: ebpf::Config,
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
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_user_timeout: Option<u64>,
        reuseaddr: Option<bool>,
    ) -> Self {
        let connect_timeout = Duration::from_secs(connect_timeout);
        let mut http_connector = connect::HttpConnector::new();
        http_connector.set_connect_timeout(Some(connect_timeout));
        if let Some(reuseaddr) = reuseaddr {
            http_connector.set_reuse_address(reuseaddr);
        }
        Connector {
            source: None,
            cidr,
            cidr_range,
            fallback,
            connect_timeout,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            tcp_user_timeout: tcp_user_timeout.map(Duration::from_secs),
            reuseaddr,
            http: http_connector,
            profile_config: ebpf::Config::default(),
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

    #[inline]
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Attach one admission's selected source without changing startup routing.
    /// `None` preserves the historical CIDR/fallback path. `Some` is strict:
    /// incompatible target families and bind/connect failures never change the
    /// source. Callers must derive this address from authorized node resources.
    pub(crate) fn with_source(mut self, source: Option<IpAddr>) -> Self {
        self.source = source;
        self
    }

    /// Retains the startup-loaded backend without attaching another program
    /// for each listener, request or selected source. Clones share its owner.
    pub(crate) fn with_profile_config(mut self, config: ebpf::Config) -> Self {
        self.profile_config = config;
        self
    }

    /// Preflight a selected TCP operation before acknowledging a tunnel. This
    /// checks backend availability only; socket/route compatibility remains a
    /// connect-time check and cannot authorize a preset on its own.
    pub(crate) fn require_profile(&self, extension: Extension) -> std::io::Result<()> {
        self.profile_config.require_backend(extension.profile())
    }
}

// ==== impl TcpConnector ====

impl TcpConnector<'_> {
    /// Applies the complete profile and keeps its cookie registration alive
    /// across the entire connect future, including SYN retransmissions. The
    /// guard is released on success/error and when timeout/cancellation drops
    /// this future. Nothing is applied to an already established connection.
    async fn connect_socket(
        &self,
        socket: TcpSocket,
        target: SocketAddr,
    ) -> std::io::Result<TcpStream> {
        if self.extension.profile().is_none() {
            // Native routes do not even query a socket cookie/address just
            // because optional profile support was compiled into the binary.
            return socket.connect(target).await;
        }
        let version = if socket.local_addr()?.is_ipv4() {
            ebpf::IpVersion::V4
        } else {
            ebpf::IpVersion::V6
        };
        self.inner
            .profile_config
            .apply(&socket, version, self.extension.profile())?;
        let _registration =
            self.inner
                .profile_config
                .register(&socket, version, self.extension.profile())?;
        socket.connect(target).await
    }

    /// Bind the admission's exact source with normal TCP socket settings, but
    /// do not connect or infer reachability. Used by forwarding and node-local
    /// bind observations. Missing strict selection is an input error; this
    /// method never consults CIDR, interface or fallback settings.
    pub(crate) fn bind_source(&self) -> std::io::Result<TcpSocket> {
        let source = self.inner.source.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "exact source is required")
        })?;
        self.create_socket_with_fallback(SocketAddr::new(source, 0), &Fallback::Address(source))
    }

    /// Returns a SocketAddr for binding (port 0). Uses CIDR, fallback IP, or default function.
    pub fn socket_addr<F>(&self, default: F) -> std::io::Result<SocketAddr>
    where
        F: FnOnce() -> std::io::Result<IpAddr>,
    {
        if let Some(source) = self.inner.source {
            return Ok(SocketAddr::new(source, 0));
        }
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
        let socket = match cidr {
            IpCidr::V4(cidr) => {
                let socket = TcpSocket::new_v4()?;
                let addr = assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension);
                socket.bind(SocketAddr::new(IpAddr::V4(addr), 0))?;
                socket
            }
            IpCidr::V6(cidr) => {
                let socket = TcpSocket::new_v6()?;
                let addr = assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension);
                socket.bind(SocketAddr::new(IpAddr::V6(addr), 0))?;
                socket
            }
        };

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(tcp_user_timeout) = self.inner.tcp_user_timeout {
            let socket_ref = socket2::SockRef::from(&socket);
            socket_ref.set_tcp_user_timeout(Some(tcp_user_timeout))?;
        }

        Ok(socket)
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

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(tcp_user_timeout) = self.inner.tcp_user_timeout {
            let socket_ref = socket2::SockRef::from(&socket);
            socket_ref.set_tcp_user_timeout(Some(tcp_user_timeout))?;
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
        self.connect_socket(socket, target_addr).await
    }

    /// Attempts to establish a TCP connection to the target address using an IP
    /// address from the provided CIDR range.
    async fn connect_with_cidr(
        &self,
        target_addr: SocketAddr,
        cidr: IpCidr,
    ) -> std::io::Result<TcpStream> {
        let socket = self.create_socket_with_cidr(cidr).await?;
        self.connect_socket(socket, target_addr).await
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
            // IPv4-mapped input uses IPv4 on the wire. Only normalize the new
            // profiled path; native source/fallback behavior stays unchanged.
            let target_addr = if self.extension.profile().is_some() {
                match target_addr {
                    SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => {
                        if address.scope_id() != 0 || address.flowinfo() != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "mapped IPv4 profile target has IPv6 metadata",
                            ));
                        }
                        SocketAddr::new(
                            IpAddr::V4(address.ip().to_ipv4_mapped().ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "invalid mapped target",
                                )
                            })?),
                            address.port(),
                        )
                    }
                    address => address,
                }
            } else {
                target_addr
            };
            let res = if let Some(source) = self.inner.source {
                if source.is_ipv4() != target_addr.is_ipv4() {
                    last_err = Some(source_family_error());
                    continue;
                }
                timeout(
                    self.inner.connect_timeout,
                    self.connect_socket(self.bind_source()?, target_addr),
                )
                .await?
            } else {
                match (self.inner.cidr, &self.inner.fallback) {
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
                        if self
                            .inner
                            .profile_config
                            .is_native(self.extension.profile())
                        {
                            timeout(self.inner.connect_timeout, TcpStream::connect(target_addr))
                                .await?
                        } else {
                            // A configured preset needs a pre-connect socket;
                            // TcpStream::connect would hide the first SYN.
                            let socket = if target_addr.is_ipv4() {
                                TcpSocket::new_v4()?
                            } else {
                                TcpSocket::new_v6()?
                            };
                            socket.set_nodelay(true)?;
                            if let Some(reuseaddr) = self.inner.reuseaddr {
                                socket.set_reuseaddr(reuseaddr)?;
                            }
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            if let Some(timeout) = self.inner.tcp_user_timeout {
                                socket2::SockRef::from(&socket)
                                    .set_tcp_user_timeout(Some(timeout))?;
                            }
                            timeout(
                                self.inner.connect_timeout,
                                self.connect_socket(socket, target_addr),
                            )
                            .await?
                        }
                    }
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
        self.inner
            .profile_config
            .require_backend(self.extension.profile())?;
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

    fn bind_ip_for_target(&self, target: SocketAddr) -> Option<IpAddr> {
        if let Some(source) = self.inner.source {
            return (source.is_ipv4() == target.is_ipv4()).then_some(source);
        }
        let ip =
            match self.inner.cidr {
                Some(IpCidr::V4(cidr)) if target.is_ipv4() => IpAddr::V4(
                    assign_ipv4_from_extension(cidr, self.inner.cidr_range, self.extension),
                ),
                Some(IpCidr::V6(cidr)) if target.is_ipv6() => IpAddr::V6(
                    assign_ipv6_from_extension(cidr, self.inner.cidr_range, self.extension),
                ),
                _ => match &self.inner.fallback {
                    Some(Fallback::Address(addr)) if addr.is_ipv4() == target.is_ipv4() => *addr,
                    #[cfg(unix)]
                    Some(Fallback::Interface(_)) => {
                        if target.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                        } else {
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                        }
                    }
                    None if self.inner.cidr.is_none() => {
                        if target.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                        } else {
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                        }
                    }
                    _ => return None,
                },
            };

        Some(ip)
    }

    async fn try_connect_targets(
        &self,
        targets: &[SocketAddr],
        preferred_family: bool,
    ) -> std::io::Result<UdpSocket> {
        let mut last_err = None;
        for &target in targets {
            let is_preferred = self.inner.cidr.is_some_and(|cidr| {
                matches!(
                    (cidr, target),
                    (IpCidr::V4(_), SocketAddr::V4(_)) | (IpCidr::V6(_), SocketAddr::V6(_))
                )
            });

            if is_preferred != preferred_family {
                continue;
            }

            let Some(bind_ip) = self.bind_ip_for_target(target) else {
                continue;
            };

            let socket = match self.create_socket(bind_ip).await {
                Ok(socket) => socket,
                Err(error) => {
                    last_err = Some(error);
                    continue;
                }
            };

            match socket.connect(target).await {
                Ok(()) => {
                    configure_udp_path(&socket)?;
                    tracing::info!("[UDP] connected {} -> {}", socket.local_addr()?, target);
                    return Ok(socket);
                }
                Err(error) => last_err = Some(error),
            }
        }
        Err(error(last_err))
    }

    async fn try_connect_fallback(&self, targets: &[SocketAddr]) -> std::io::Result<UdpSocket> {
        let Some(Fallback::Address(fallback)) = &self.inner.fallback else {
            return Err(error(None));
        };

        let mut last_err = None;

        for &target in targets {
            if fallback.is_ipv4() != target.is_ipv4() {
                continue;
            }

            let socket = match self.create_socket(*fallback).await {
                Ok(socket) => socket,
                Err(error) => {
                    last_err = Some(error);
                    continue;
                }
            };

            match socket.connect(target).await {
                Ok(()) => {
                    configure_udp_path(&socket)?;
                    tracing::info!("[UDP] connected {} -> {}", socket.local_addr()?, target);
                    return Ok(socket);
                }
                Err(error) => last_err = Some(error),
            }
        }

        Err(error(last_err))
    }

    pub(crate) async fn connect(&self, targets: &[SocketAddr]) -> std::io::Result<UdpSocket> {
        if let Some(source) = self.inner.source {
            // Bind exactly once for this CONNECT-UDP stream. A failed bind must
            // not become a successful probe/flow on a different local address.
            let socket = self.create_socket(source).await?;
            let mut last_err = None;
            for &target in targets {
                if source.is_ipv4() != target.is_ipv4() {
                    last_err = Some(source_family_error());
                    continue;
                }
                match socket.connect(target).await {
                    Ok(()) => {
                        configure_udp_path(&socket)?;
                        return Ok(socket);
                    }
                    Err(error) => last_err = Some(error),
                }
            }
            return Err(error(last_err));
        }
        if self.inner.cidr.is_some() {
            match self.try_connect_targets(targets, true).await {
                Ok(socket) => return Ok(socket),
                Err(error) if targets.is_empty() => return Err(error),
                Err(_) => {}
            }
            if let Ok(socket) = self.try_connect_fallback(targets).await {
                return Ok(socket);
            }
        }
        self.try_connect_targets(targets, false).await
    }

    /// Binds UDP sockets based on the configured CIDR and fallback IP address.
    /// If both CIDR and fallback are provided and belong to different IP families,
    /// it creates two sockets for dual-stack support. Otherwise, it creates a single
    /// socket based on the available configuration.
    pub async fn create_socket_dual_stack(
        &self,
    ) -> std::io::Result<(UdpSocket, Option<UdpSocket>)> {
        if let Some(source) = self.inner.source {
            return Ok((self.create_socket(source).await?, None));
        }
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
        if let Some(source) = self.inner.source {
            if source.is_ipv4() != addr.is_ipv4() || preferred_outbound.local_addr()?.ip() != source
            {
                return Err(source_family_error());
            }
            // An association keeps its admission's socket. In strict mode even
            // a supplied fallback socket is never polled or used.
            return self.try_send_to_addr(pkt, addr, preferred_outbound).await;
        }
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
            tracing::trace!(
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

#[cfg(any(target_os = "linux", target_os = "android"))]
fn configure_udp_path(socket: &UdpSocket) -> std::io::Result<()> {
    use rustix::net::sockopt::{
        Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery, set_ip_mtu_discover, set_ipv6_mtu_discover,
    };

    // RFC 9298 forbids the proxy from introducing IP fragmentation. PROBE
    // preserves datagram boundaries and reports an oversized send as EMSGSIZE.
    // https://www.rfc-editor.org/rfc/rfc9298.html#section-6
    if socket.peer_addr()?.is_ipv4() {
        set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::PROBE)?;
    } else {
        set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::PROBE)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn configure_udp_path(socket: &UdpSocket) -> std::io::Result<()> {
    let state = quinn_udp::UdpSocketState::new(socket.into())?;
    if state.may_fragment() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the platform cannot guarantee that UDP datagrams will not be fragmented",
        ));
    }
    Ok(())
}

// ==== impl HttpConnector ====

impl HttpConnector<'_> {
    /// Sends an HTTP request using the configured `HttpConnector`.
    pub async fn send_request<B>(
        self,
        req: Request<B>,
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if self.inner.source.is_some() || self.extension.profile().is_some() {
            // HttpConnector::set_local_address selects a preference, not an
            // allowlist: the other destination family can still connect with
            // an OS-selected source. Reuse our strict TCP path instead, while
            // retaining Hyper's request framing, Host and origin-form handling.
            let mut builder = Client::builder(TokioExecutor::new());
            // Keep DATA Buf advancement tied to successful H1 writes instead
            // of a pre-write flattening copy used by the automatic strategy.
            #[cfg(feature = "management")]
            builder.http1_writev(true);
            return builder
                .timer(TokioTimer::new())
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(ExactConnector(self.inner.clone(), self.extension))
                .request(req)
                .await;
        }
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

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(tcp_user_timeout) = self.inner.tcp_user_timeout {
            connector.set_tcp_user_timeout(Some(tcp_user_timeout));
        }

        let mut builder = Client::builder(TokioExecutor::new());
        #[cfg(feature = "management")]
        builder.http1_writev(true);
        builder
            .timer(TokioTimer::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(connector)
            .request(req)
            .await
    }
}

/// Hyper's adapter for an authorized source or a pre-connect preset. It uses
/// the same TCP socket path as CONNECT, preserving strict source-family checks
/// and keeping cookie registration alive until connect completes. No pool is
/// shared across users, exits or presets; each operation builds its own client.
#[derive(Clone)]
struct ExactConnector(Connector, Extension);

impl tower_service::Service<http::Uri> for ExactConnector {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let connector = self.0.clone();
        let extension = self.1;
        Box::pin(async move {
            if uri.scheme_str() != Some("http") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTP forwarding requires an http target",
                ));
            }
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing HTTP target host")
            })?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let stream = timeout(
                connector.connect_timeout,
                connector
                    .tcp(extension)
                    .connect((host.to_owned(), uri.port_u16().unwrap_or(80))),
            )
            .await??;
            Ok(TokioIo::new(stream))
        })
    }
}

fn source_family_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "target or socket does not match the authorized source address",
    )
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
        match extension.route() {
            RouteExtension::TTL(_) | RouteExtension::Session(_) => {
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
            RouteExtension::Range(_) => {
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
        match extension.route() {
            RouteExtension::TTL(_) | RouteExtension::Session(_) => {
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
            RouteExtension::Range(_) => {
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
    if u32::from(prefix_len) >= Ipv4Addr::BITS {
        return cidr.first_address();
    }
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
    if u32::from(prefix_len) >= Ipv6Addr::BITS {
        return cidr.first_address();
    }
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
    match extension.route() {
        RouteExtension::Range(value) => Some(value),
        RouteExtension::Session(value) => Some(value),
        RouteExtension::TTL(ttl) => Some(ttl),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_target_prefers_cidr_family_and_uses_fallback_for_the_other_family() {
        let connector = Connector::new(
            Some("2001:db8::1/128".parse().expect("valid IPv6 CIDR")),
            None,
            Some(Fallback::Address(Ipv4Addr::LOCALHOST.into())),
            10,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        );
        let udp = connector.udp(Extension::None);

        assert_eq!(
            udp.bind_ip_for_target("192.0.2.1:443".parse().expect("valid IPv4 target")),
            Some(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(
            udp.bind_ip_for_target("[2001:db8::2]:443".parse().expect("valid IPv6 target")),
            Some("2001:db8::1".parse().expect("valid IPv6 address"))
        );
    }

    #[tokio::test]
    async fn udp_connect_uses_same_family_fallback_when_cidr_bind_fails() {
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP target");
        let connector = Connector::new(
            Some("192.0.2.1/32".parse().expect("valid IPv4 CIDR")),
            None,
            Some(Fallback::Address(Ipv4Addr::LOCALHOST.into())),
            10,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        );

        let socket = connector
            .udp(Extension::None)
            .connect(&[target.local_addr().expect("target address")])
            .await
            .expect("fallback connects");
        assert_eq!(
            socket.local_addr().expect("local address").ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

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

#[cfg(test)]
mod source_tests {
    //! Exact-source regressions observe real sockets: successful binding is not
    //! enough if a second address family or a supplied fallback can escape it.

    use http_body_util::BodyExt as _;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::*;
    const SELECTED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    /// Some native hosts have IPv6 disabled, including ::1. Only that explicit
    /// fixture limitation is optional; permission/resource/other I/O failures must
    /// still fail. The caller continues its constructed-V6 strict-family checks
    /// and all real IPv4 forwarding assertions rather than skipping the test.
    fn ipv6_fixture<T>(result: std::io::Result<T>) -> Option<T> {
        match result {
            Ok(socket) => Some(socket),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                ) =>
            {
                eprintln!(
                    "IPv6 loopback fixture unavailable ({:?}); constructed-V6 and real IPv4 checks remain active",
                    error.kind()
                );
                None
            }
            Err(error) => panic!("unexpected IPv6 fixture failure: {error}"),
        }
    }

    fn connector(source: IpAddr) -> Connector {
        Connector::new(
            Some("192.0.2.1/32".parse().unwrap()),
            None,
            Some(Fallback::Address(Ipv6Addr::LOCALHOST.into())),
            1,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            Some(true),
        )
        .with_source(Some(source))
    }

    #[tokio::test]
    async fn unavailable_profile_never_connects_via_native_or_strict_fallback() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = target.local_addr().unwrap();
        let extension = Extension::Profiled {
            route: RouteExtension::Session(42),
            profile: crate::ebpf::Profile::Windows,
        };
        for config in [
            connector(SELECTED.into()),
            connector(SELECTED.into()).with_source(None),
        ] {
            let error = config.tcp(extension).connect(address).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            let request = Request::builder()
                .uri(format!("http://{address}/"))
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            assert!(config.http(extension).send_request(request).await.is_err());
        }
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );

        // A SYN preset is not an implicit change to UDP policy or source binding.
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let config = connector(SELECTED.into());
        let selected = config
            .udp(extension)
            .connect(&[udp.local_addr().unwrap()])
            .await
            .unwrap();
        selected.send(b"still-udp").await.unwrap();
        let mut bytes = [0; 16];
        let (size, peer) = timeout(Duration::from_secs(1), udp.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..size], b"still-udp");
        assert_eq!(peer.ip(), IpAddr::V4(SELECTED));
    }

    #[tokio::test]
    async fn strict_tcp_filters_family_and_binds_selected_source_including_bind_address() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let config = connector(SELECTED.into());
        let tcp = config.tcp(Extension::Session(42));
        assert_eq!(
            tcp.socket_addr(|| panic!("strict source must not use a default"))
                .unwrap(),
            SocketAddr::from((SELECTED, 0)),
        );
        let addresses = [
            SocketAddr::from((Ipv6Addr::LOCALHOST, target_addr.port())),
            target_addr,
        ];
        let connected = tcp.connect_with_addrs(addresses).await.unwrap();
        let (_, peer) = target.accept().await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(SELECTED));
        assert_eq!(connected.local_addr().unwrap().ip(), peer.ip());

        let incompatible = ipv6_fixture(TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await);
        let incompatible_addr = incompatible.as_ref().map_or_else(
            || SocketAddr::from((Ipv6Addr::LOCALHOST, target_addr.port())),
            |listener| listener.local_addr().unwrap(),
        );
        assert_eq!(
            tcp.connect(incompatible_addr).await.unwrap_err().kind(),
            std::io::ErrorKind::AddrNotAvailable
        );
        if let Some(incompatible) = incompatible {
            assert!(
                timeout(Duration::from_millis(100), incompatible.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn strict_udp_keeps_one_socket_and_never_uses_a_supplied_fallback() {
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let config = connector(SELECTED.into());
        let udp = config.udp(Extension::None);
        let (socket, fallback) = udp.create_socket_dual_stack().await.unwrap();
        assert!(fallback.is_none());
        assert_eq!(socket.local_addr().unwrap().ip(), IpAddr::V4(SELECTED));
        let target_addr = target.local_addr().unwrap();
        let native_fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        assert_eq!(
            udp.send_packet(b"bound", target_addr, &socket, Some(&native_fallback))
                .await
                .unwrap(),
            5
        );
        let mut bytes = [0; 16];
        let (size, peer) = timeout(Duration::from_secs(1), target.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..size], b"bound");
        assert_eq!(peer, socket.local_addr().unwrap());

        let other = ipv6_fixture(UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await);
        let other_addr = other.as_ref().map_or_else(
            || SocketAddr::from((Ipv6Addr::LOCALHOST, target_addr.port())),
            |socket| socket.local_addr().unwrap(),
        );
        let fallback = match &other {
            Some(_) => Some(UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap()),
            None => None,
        };
        assert_eq!(
            udp.send_packet(
                b"forbidden",
                other_addr,
                &socket,
                Some(fallback.as_ref().unwrap_or(&native_fallback))
            )
            .await
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::AddrNotAvailable
        );
        if let Some(other) = &other {
            assert!(
                timeout(Duration::from_millis(100), other.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        }

        // Even without IPv6, a real same-family fallback must not let a caller
        // supply a different source socket and escape the authorized address.
        assert_eq!(
            udp.send_packet(
                b"wrong-source",
                target_addr,
                &native_fallback,
                Some(&native_fallback)
            )
            .await
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::AddrNotAvailable
        );
        assert!(
            timeout(Duration::from_millis(100), target.recv_from(&mut bytes))
                .await
                .is_err()
        );

        let targets = [other_addr, target_addr];
        let connected = udp.connect(&targets).await.unwrap();
        assert_eq!(connected.peer_addr().unwrap(), target_addr);
        assert_eq!(connected.local_addr().unwrap().ip(), IpAddr::V4(SELECTED));
        connected.send(b"candidate").await.unwrap();
        let (size, peer) = timeout(Duration::from_secs(1), target.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..size], b"candidate");
        assert_eq!(peer.ip(), IpAddr::V4(SELECTED));
    }

    #[tokio::test]
    async fn strict_http_observes_source_and_preserves_origin_form_without_family_escape() {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = target.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, peer) = target.accept().await.unwrap();
            let mut request = Vec::new();
            let mut bytes = [0; 512];
            while !request.windows(4).any(|value| value == b"\r\n\r\n") {
                let size = stream.read(&mut bytes).await.unwrap();
                assert!(size > 0 && request.len() + size <= 8192);
                request.extend_from_slice(&bytes[..size]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            (peer, String::from_utf8(request).unwrap())
        });
        let config = connector(SELECTED.into());
        let request = Request::builder()
            .uri(format!("http://{addr}/path?key=value"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let response = timeout(
            Duration::from_secs(2),
            config.http(Extension::None).send_request(request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            &response.into_body().collect().await.unwrap().to_bytes()[..],
            b"ok"
        );
        let (peer, request) = origin.await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(SELECTED));
        assert!(request.starts_with("GET /path?key=value HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: {addr}\r\n"))
        );

        let other = ipv6_fixture(TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await);
        let other_addr = other.as_ref().map_or_else(
            || SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())),
            |listener| listener.local_addr().unwrap(),
        );
        let request = Request::builder()
            .uri(format!("http://{other_addr}/"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        assert!(
            config
                .http(Extension::None)
                .send_request(request)
                .await
                .is_err()
        );
        if let Some(other) = other {
            assert!(
                timeout(Duration::from_millis(100), other.accept())
                    .await
                    .is_err()
            );
        }
    }
}
