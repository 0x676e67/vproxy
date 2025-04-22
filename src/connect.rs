use super::{extension::Extension, http::error::Error};
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use futures_util::future::Either;
use http::{Request, Response, uri::Authority};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{Client, connect},
    rt::{TokioExecutor, TokioTimer},
};
use rand::random;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    time::timeout,
};

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

impl Connector {
    /// Constructs a new `Connector` instance, accepting optional IPv6 CIDR and
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

    /// Returns a new instance of `HttpConnector` configured with the same settings
    /// as the current `Connector`.
    ///
    /// This method clones the internal `HttpConnector` and copies the CIDR, CIDR range,
    /// and fallback IP address settings from the current `Connector` instance.
    ///
    /// # Returns
    ///
    /// A new `HttpConnector` instance with the same configuration as the current `Connector`.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let http_connector = connector.http_connector();
    /// ```
    #[inline(always)]
    pub fn http_connector(&self) -> HttpConnector {
        HttpConnector { inner: self }
    }

    /// Returns a new instance of `TcpConnector` configured with the same settings
    /// as the current `Connector`.
    ///
    /// This method copies the CIDR, CIDR range, fallback IP address, and connect timeout
    /// settings from the current `Connector` instance.
    ///
    /// # Returns
    ///
    /// A new `TcpConnector` instance with the same configuration as the current `Connector`.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = connector.tcp_connector();
    /// ```
    #[inline(always)]
    pub fn tcp_connector(&self) -> TcpConnector {
        TcpConnector { inner: self }
    }

    /// Returns a new instance of `UdpConnector` configured with the same settings
    /// as the current `Connector`.
    /// This method copies the CIDR, CIDR range, fallback IP address, and connect timeout
    /// settings from the current `Connector` instance.
    /// # Returns
    /// A new `UdpConnector` instance with the same configuration as the current `Connector`.
    /// # Example
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let udp_connector = connector.udp_connector();
    /// ```
    #[inline(always)]
    pub fn udp_connector(&self) -> UdpConnector {
        UdpConnector { inner: self }
    }
}

/// A `TcpConnector` is responsible for establishing TCP connections with
/// the specified configuration settings.
///
/// The `TcpConnector` struct holds configuration settings such as CIDR,
/// CIDR range, fallback IP address, and connection timeout. These settings
/// are used to configure and establish TCP connections.
///
/// # Fields
///
/// * `cidr` - An optional CIDR range to assign the IP address from.
/// * `cidr_range` - An optional CIDR range value.
/// * `fallback` - An optional fallback IP address to use if the primary
///   address assignment fails.
/// * `connect_timeout` - The timeout duration for establishing a connection.
///
/// # Example
///
/// ```
/// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
/// let tcp_connector = connector.tcp_connector();
/// ```
pub struct TcpConnector<'a> {
    inner: &'a Connector,
}

impl TcpConnector<'_> {
    /// Binds a socket to an IP address based on the provided CIDR, fallback IP, and extensions.
    ///
    /// This method determines the appropriate IP address to bind the socket to based on the
    /// configuration of the `Connector`. It first checks if a CIDR range is provided. If so,
    /// it assigns an IP address from the CIDR range using the provided extensions. If no CIDR
    /// range is provided but a fallback IP address is available, it uses the fallback IP address.
    /// If neither is available, it uses the default IP address provided as an argument.
    ///
    /// # Arguments
    ///
    /// * `default` - The default IP address to use if no CIDR or fallback IP is available.
    /// * `extension` - The extensions used to determine the IP address from the CIDR range.
    ///
    /// # Returns
    ///
    /// A `SocketAddr` representing the bound address.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = TcpConnector { inner: &connector };
    /// let socket_addr = tcp_connector.bind_socket_addr(default_ip, extension);
    /// ```
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
    ///
    /// This function takes an `IntoIterator` of `SocketAddr` for the target
    /// addresses and an `Extensions` reference. It attempts to connect to
    /// each target address in turn using the `try_connect_with_iter` function.
    ///
    /// If a connection to any of the target addresses is established, it
    /// returns the connected `TcpStream`. If all connection attempts fail,
    /// it returns the last error encountered. If no connection attempts were
    /// made because the iterator is empty, it returns a `ConnectionAborted`
    /// error.
    ///
    /// # Arguments
    ///
    /// * `addrs` - An `IntoIterator` of the target addresses to connect to.
    /// * `extension` - A reference to the extensions to use for the connection
    ///   attempt.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an
    /// error at any step, it returns the error in the `Result`.
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
    ///
    /// This method takes an `Authority` and an `Extension` as arguments. It resolves
    /// the authority to a list of socket addresses and attempts to connect to each
    /// address in turn using the `connect` method. If a connection is successfully
    /// established, it returns the connected `TcpStream`. If all connection attempts
    /// fail, it returns the last encountered error.
    ///
    /// # Arguments
    ///
    /// * `authority` - The authority (host:port) to resolve and connect to.
    /// * `extension` - The extensions used during the connection process.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<TcpStream>` representing the result of the connection attempt.
    /// If successful, it returns `Ok(TcpStream)`. If all attempts fail, it returns the
    /// last encountered error.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = TcpConnector { inner: &connector };
    /// let authority = "example.com:80".parse().unwrap();
    /// let extension = Extension::default();
    /// let stream = tcp_connector.connect_with_authority(authority, extension).await?;
    /// ```
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
    ///
    /// This function takes a tuple of a `String` and a `u16` for the host and
    /// port of the target domain and an `Extensions` reference. It resolves
    /// the host to a list of IP addresses using the `lookup_host` function and
    /// then attempts to connect to each IP address in turn using the
    /// `try_connect_with_iter` function.
    ///
    /// If a connection to any of the IP addresses is established, it returns
    /// the connected `TcpStream`. If all connection attempts fail, it
    /// returns the last error encountered. If no connection attempts were made
    /// because the host could not be resolved to any IP addresses,
    /// it returns a `ConnectionAborted` error.
    ///
    /// # Arguments
    ///
    /// * `host` - The host and port of the target domain.
    /// * `extension` - A reference to the extensions to use for the connection
    ///   attempt.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an
    /// error at any step, it returns the error in the `Result`.
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
    ///
    /// This function takes a `SocketAddr` for the target address and an
    /// `Extensions` reference. It first checks the type of the extension.
    /// If the extension is `Http2Socks5`, it attempts to connect to the target
    /// address via the SOCKS5 proxy using the `try_connect_to_socks5` function.
    /// If the extension is `None` or `Session`, it checks the CIDR range and
    /// fallback IP address.
    ///
    /// If only the CIDR range is provided, it attempts to connect to the target
    /// address using an IP address from the CIDR range with the
    /// `try_connect_with_cidr` function. If only the fallback IP address is
    /// provided, it attempts to connect to the target address using the
    /// fallback IP address with the `try_connect_with_fallback` function.
    /// If both the CIDR range and fallback IP address are provided, it attempts
    /// to connect to the target address using an IP address from the CIDR range
    /// and falls back to the fallback IP address if the connection attempt
    /// fails with the `try_connect_with_cidr_and_fallback` function.
    /// If neither the CIDR range nor the fallback IP address is provided, it
    /// attempts to connect to the target address directly using
    /// `TcpStream::connect`.
    ///
    /// Each connection attempt is wrapped in a timeout. If the connection
    /// attempt does not complete within the timeout, it is cancelled and a
    /// `TimedOut` error is returned.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target address to connect to.
    /// * `extension` - A reference to the extensions to use for the connection
    ///   attempt.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an
    /// error at any step, it returns the error in the `Result`.
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
    ///
    /// This function takes a `SocketAddr` for the target address, an `IpCidr` for
    /// the CIDR range, and an `Extensions` reference for assigning the IP address.
    /// It creates a socket and assigns an IP address from the CIDR range using the
    /// `create_socket_with_cidr` function. It then attempts to connect to the
    /// target address using the created socket.
    ///
    /// If the connection attempt is successful, it returns the connected
    /// `TcpStream`. If the connection attempt fails, it returns the error in the
    /// `Result`.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target address to connect to.
    /// * `cidr` - The CIDR range to assign the IP address from.
    /// * `extension` - A reference to the extensions to use when assigning the IP
    ///   address.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an error at
    /// any step, it returns the error in the `Result`.
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
    ///
    /// This function takes a `SocketAddr` for the target address and an `IpAddr`
    /// for the fallback IP address. It creates a socket and binds it to the
    /// fallback IP address using the `create_socket_with_ip` function.
    /// It then attempts to connect to the target address using the created socket.
    ///
    /// If the connection attempt is successful, it returns the connected
    /// `TcpStream`. If the connection attempt fails, it returns the error in the
    /// `Result`.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target address to connect to.
    /// * `fallback` - The fallback IP address to use for the connection attempt.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an error at
    /// any step, it returns the error in the `Result`.
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
    ///
    /// This function takes a `SocketAddr` for the target address, an `IpCidr` for
    /// the CIDR range, an `IpAddr` for the fallback IP address, and an `Extensions`
    /// reference for assigning the IP address. It first creates a socket and
    /// assigns an IP address from the CIDR range
    /// using the `create_socket_with_cidr` function. It then attempts to connect to
    /// the target address using the created socket.
    ///
    /// If the connection attempt is successful, it returns the connected
    /// `TcpStream`. If the connection attempt fails, it logs the error
    /// and then attempts to connect to the target address using the fallback IP
    /// address with the `try_connect_with_fallback` function.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The target address to connect to.
    /// * `cidr` - The CIDR range to assign the IP address from.
    /// * `fallback` - The fallback IP address to use if the connection attempt
    ///   fails.
    /// * `extension` - A reference to the extensions to use when assigning the IP
    ///   address.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpStream>`. If a connection is
    /// successfully established, it returns `Ok(stream)`. If there is an error at
    /// any step, it returns the error in the `Result`.
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
    ///
    /// This function takes an `IpAddr` reference as an argument and creates a new
    /// TCP socket based on the IP version. If the IP address is IPv4, it creates a
    /// new IPv4 socket. If the IP address is IPv6, it creates a new IPv6 socket.
    /// After creating the socket, it binds the socket to the provided IP address on
    /// port 0.
    ///
    /// # Arguments
    ///
    /// * `ip` - A reference to the IP address to bind the socket to.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpSocket>`. If the socket is
    /// successfully created and bound, it returns `Ok(socket)`. If there is an
    /// error creating or binding the socket, it returns the error in the `Result`.
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

    /// Creates a TCP socket and binds it to an IP address within the provided CIDR
    /// range.
    ///
    /// This function takes an `IpCidr` and an `Extensions` reference as arguments.
    /// It creates a new TCP socket based on the IP version of the CIDR. If the CIDR
    /// is IPv4, it creates a new IPv4 socket and assigns an IPv4 address from the
    /// CIDR range using the `assign_ipv4_from_extension` function. If the CIDR is
    /// IPv6, it creates a new IPv6 socket and assigns an IPv6 address from the CIDR
    /// range using the `assign_ipv6_from_extension` function. After creating the
    /// socket and assigning the IP address, it binds the socket to the assigned IP
    /// address on port 0.
    ///
    /// # Arguments
    ///
    /// * `cidr` - The CIDR range to assign the IP address from.
    /// * `extension` - A reference to the extensions to use when assigning the IP
    ///   address.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<TcpSocket>`. If the socket is
    /// successfully created, assigned an IP address, and bound, it returns
    /// `Ok(socket)`. If there is an error at any step, it returns the error in the
    /// `Result`.
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

/// `UdpConnector` struct is used to create UDP connectors, optionally configured
/// with an IPv6 CIDR and a fallback IP address.
///
/// This struct provides methods to bind UDP sockets to appropriate IP addresses
/// based on the configuration of the `Connector`.
pub struct UdpConnector<'a> {
    inner: &'a Connector,
}

impl UdpConnector<'_> {
    /// Binds a UDP socket to an IP address based on the provided CIDR, fallback IP, and extensions.
    ///
    /// This method determines the appropriate IP address to bind the socket to based on the
    /// configuration of the `Connector`. It first checks if a CIDR range is provided. If so,
    /// it assigns an IP address from the CIDR range using the provided extensions. If no CIDR
    /// range is provided but a fallback IP address is available, it uses the fallback IP address.
    /// If neither is available, it binds to a default address.
    ///
    /// # Arguments
    ///
    /// * `extension` - The extensions used to determine the IP address from the CIDR range.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<UdpSocket>` representing the result of the binding attempt.
    /// If successful, it returns `Ok(UdpSocket)`. If the binding fails, it returns the
    /// encountered error.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = TcpConnector { inner: &connector };
    /// let extension = Extension::default();
    /// let udp_socket = tcp_connector.bind_socket(extension).await?;
    /// ```
    #[inline(always)]
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
    ///
    /// This method sends a UDP packet to the specified destination address using the provided
    /// UDP socket.
    ///
    /// # Arguments
    ///
    /// * `dispatch_socket` - The UDP socket used to send the packet.
    /// * `pkt` - The packet data to be sent.
    /// * `dst_addr` - The destination address to send the packet to.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<()>` representing the result of the send attempt.
    /// If successful, it returns `Ok(())`. If the send fails, it returns the encountered error.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = TcpConnector { inner: &connector };
    /// let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    /// let pkt = b"Hello, world!";
    /// let dst_addr = "127.0.0.1:8080".parse().unwrap();
    /// tcp_connector.send_packet_with_addr(&udp_socket, pkt, dst_addr).await?;
    /// ```
    #[inline(always)]
    pub async fn send_packet_with_addr(
        &self,
        dispatch_socket: &UdpSocket,
        pkt: &[u8],
        dst_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        dispatch_socket.send_to(pkt, dst_addr).await
    }

    /// Sends a UDP packet to the specified domain and port using the provided UDP socket.
    ///
    /// This method resolves the domain to an IP address and sends a UDP packet to the specified
    /// destination domain and port using the provided UDP socket.
    ///
    /// # Arguments
    ///
    /// * `dispatch_socket` - The UDP socket used to send the packet.
    /// * `pkt` - The packet data to be sent.
    /// * `dst_domain` - A tuple containing the destination domain and port.
    ///
    /// # Returns
    ///
    /// A `std::io::Result<()>` representing the result of the send attempt.
    /// If successful, it returns `Ok(())`. If the send fails, it returns the encountered error.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
    /// let tcp_connector = TcpConnector { inner: &connector };
    /// let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    /// let pkt = b"Hello, world!";
    /// let dst_domain = ("example.com".to_string(), 8080);
    /// tcp_connector.send_packet_with_domain(&udp_socket, pkt, dst_domain).await?;
    /// ```
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
    ///
    /// This function takes an `IpAddr` reference as an argument and creates a new
    /// UDP socket based on the IP version. If the IP address is IPv4, it creates a
    /// new IPv4 socket. If the IP address is IPv6, it creates a new IPv6 socket.
    /// After creating the socket, it binds the socket to the provided IP address on
    /// port 0.
    ///
    /// # Arguments
    ///
    /// * `ip` - A reference to the IP address to bind the socket to.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<UdpSocket>`. If the socket is
    /// successfully created and bound, it returns `Ok(socket)`. If there is an
    /// error creating or binding the socket, it returns the error in the `Result`.
    #[inline]
    async fn create_socket_with_addr(&self, ip: IpAddr) -> std::io::Result<UdpSocket> {
        UdpSocket::bind(SocketAddr::new(ip, 0)).await
    }

    /// Creates a UDP socket and binds it to an IP address within the provided CIDR
    /// range.
    ///
    /// This function takes an `IpCidr` and an `Extensions` reference as arguments.
    /// It creates a new UDP socket based on the IP version of the CIDR. If the CIDR
    /// is IPv4, it creates a new IPv4 socket and assigns an IPv4 address from the
    /// CIDR range using the `assign_ipv4_from_extension` function. If the CIDR is
    /// IPv6, it creates a new IPv6 socket and assigns an IPv6 address from the CIDR
    /// range using the `assign_ipv6_from_extension` function. After creating the
    /// socket and assigning the IP address, it binds the socket to the assigned IP
    /// address on port 0.
    ///
    /// # Arguments
    ///
    /// * `cidr` - The CIDR range to assign the IP address from.
    /// * `extension` - A reference to the extensions to use when assigning the IP
    ///   address.
    ///
    /// # Returns
    ///
    /// This function returns a `std::io::Result<UdpSocket>`. If the socket is
    /// successfully created, assigned an IP address, and bound, it returns
    /// `Ok(socket)`. If there is an error at any step, it returns the error in the
    /// `Result`.
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
    /// This function takes an `IpCidr` for the CIDR range, an `IpAddr` for the fallback
    /// IP address, and an `Extensions` reference for assigning the IP address. It first
    /// creates a socket and assigns an IP address from the CIDR range using the
    /// `create_socket_with_cidr` function. It then attempts to bind the socket to the
    /// assigned IP address. If the binding is successful, it returns the bound `UdpSocket`.
    /// If the binding fails, it logs the error and then attempts to bind the socket to the
    /// fallback IP address using the `create_socket_with_addr` function.
    /// # Arguments
    /// * `cidr` - The CIDR range to assign the IP address from.
    /// * `fallback` - The fallback IP address to use if the binding fails.
    /// * `extension` - A reference to the extensions to use when assigning the IP address.
    /// # Returns
    /// This function returns a `std::io::Result<UdpSocket>`. If the socket is successfully
    /// created, assigned an IP address, and bound, it returns `Ok(socket)`. If there is an
    /// error at any step, it returns the error in the `Result`.
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

/// A `HttpConnector` is responsible for establishing HTTP connections with
/// the specified configuration settings.
///
/// The `HttpConnector` struct holds configuration settings such as CIDR,
/// CIDR range, fallback IP address, and connection timeout. These settings
/// are used to configure and establish HTTP connections.
///
/// # Fields
///
/// * `inner` - The internal `connect::HttpConnector` used for establishing connections.
/// * `cidr` - An optional CIDR range to assign the IP address from.
/// * `cidr_range` - An optional CIDR range value.
/// * `fallback` - An optional fallback IP address to use if the primary
///   address assignment fails.
///
/// # Example
///
/// ```
/// let connector = Connector::new(Some(cidr), Some(cidr_range), Some(fallback), connect_timeout);
/// let http_connector = connector.http_connector();
/// ```
pub struct HttpConnector<'a> {
    inner: &'a Connector,
}

impl HttpConnector<'_> {
    /// Sends an HTTP request using the configured `HttpConnector`.
    ///
    /// This method sets the local addresses based on the provided CIDR and fallback IP address,
    /// and then sends the HTTP request.
    ///
    /// # Arguments
    ///
    /// * `req` - The HTTP request to be sent.
    /// * `extension` - The extension used to determine the local addresses.
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response if the request was successful, or an `Error` if it failed.
    ///
    /// # Example
    ///
    /// ```
    /// let connector = HttpConnector::new(Some(cidr), Some(cidr_range), Some(fallback));
    /// let response = connector.send_request(request, extension).await?;
    /// ```
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
///
/// This function takes an `Option<std::io::Error>` for the last error
/// encountered. If an error is provided, it logs the error and returns it.
/// If no error is provided, it returns a `ConnectionAborted` error with the
/// message "Failed to connect to any resolved address".
///
/// # Arguments
///
/// * `last_err` - An `Option<std::io::Error>` for the last error encountered.
///
/// # Returns
///
/// This function returns a `std::io::Error`. If an error is provided, it
/// returns the provided error. If no error is provided, it returns a
/// `ConnectionAborted` error.
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
///
/// # Parameters
/// - `cidr`: The CIDR notation representing the network range, e.g., "192.168.0.0/24".
/// - `range`: The length of the address range to be fixed by the combined value (e.g., 28 for a /28 subnet).
/// - `combined`: A fixed value used to influence the specific address within the range.
///
/// # Returns
/// An `Ipv4Addr` representing the generated IPv4 address.
///
/// # Example
/// ```
/// let cidr = "192.168.0.0/24".parse::<Ipv4Cidr>().unwrap();
/// let range = 28;
/// let combined = 0x5;
/// let ipv4_address = assign_ipv4_with_range(&cidr, range, combined);
/// println!("Generated IPv4 Address: {}", ipv4_address);
/// ```
fn assign_ipv4_with_range(cidr: Ipv4Cidr, range: u8, combined: u32) -> Ipv4Addr {
    let base_ip: u32 = u32::from(cidr.first_address());
    let prefix_len = cidr.network_length();

    // If the range is less than the prefix length, generate a random IP address.
    if range < prefix_len {
        return assign_rand_ipv4(cidr);
    }

    // Shift the combined value to the left by (32 - range) bits to place it in the correct position.
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
///
/// # Parameters
/// - `cidr`: The CIDR notation representing the network range, e.g., "2001:470:e953::/48".
/// - `range`: The length of the address range to be fixed by the combined value (e.g., 64 for a /64 subnet).
/// - `combined`: A fixed value used to influence the specific address within the range.
///
/// # Returns
/// An `Ipv6Addr` representing the generated IPv6 address.
///
/// # Example
/// ```
/// let cidr = "2001:470:e953::/48".parse::<Ipv6Cidr>().unwrap();
/// let range = 64;
/// let combined = 0x12345;
/// let ipv6_address = assign_ipv6_with_range(&cidr, range, combined);
/// println!("Generated IPv6 Address: {}", ipv6_address);
/// ```
fn assign_ipv6_with_range(cidr: Ipv6Cidr, range: u8, combined: u128) -> Ipv6Addr {
    let base_ip: u128 = cidr.first_address().into();
    let prefix_len = cidr.network_length();

    // If the range is less than the prefix length, generate a random IP address.
    if range < prefix_len {
        return assign_rand_ipv6(cidr);
    }

    // Shift the combined value to the left by (128 - range) bits to place it in the correct position.
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
/// not contain a value (i.e., it is not one of the aforementioned variants), the function returns `None`.
///
/// # Arguments
///
/// * `extension` - An `Extension` enum variant from which to extract the value.
///
/// # Returns
///
/// * `Option<u64>` - The extracted value if the `extension` is a `Range`, `Session`, or `TTL` variant; otherwise, `None`.
///
/// # Examples
///
/// ```
/// let ext = Extension::Range(42);
/// assert_eq!(extract_value_from_extension(ext), Some(42));
///
/// let ext = Extension::Unknown;
/// assert_eq!(extract_value_from_extension(ext), None);
/// ```
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

            println!("IPv4 Address 1: {}", ipv4_address1);
            println!("IPv4 Address 2: {}", ipv4_address2);
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

            println!("{}", ipv6_address1);
            println!("{}", ipv6_address2)
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
