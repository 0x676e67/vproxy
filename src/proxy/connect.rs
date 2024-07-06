use super::{
    extension::Extensions,
    http::error::ProxyError,
    socks5::{self, proto::UsernamePassword},
};
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

    /// Asynchronously creates and sends a new HTTP request with custom local
    /// addresses.
    ///
    /// This method constructs an `HttpConnector` and sets its local addresses
    /// based on the provided CIDR and fallback IP configuration. It then
    /// sends the request using a hyper `Client` and returns the response or
    /// a `ProxyError` if the request fails.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request to be forwarded.
    /// * `extension` - Additional data used for setting local addresses based
    ///   on CIDR.
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response on success, or a `ProxyError` on
    /// failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let response = proxy.new_http_request(request, extensions).await?;
    /// ```
    ///
    /// # Details
    ///
    /// The method checks the provided CIDR and fallback IP configuration and
    /// sets the local addresses of the connector accordingly:
    ///
    /// * If both CIDR (IPv4) and fallback (IPv6) are provided, it assigns a
    ///   local IPv4 address from the CIDR and sets both IPv4 and IPv6
    ///   addresses.
    /// * If only CIDR (IPv4) is provided, it assigns a local IPv4 address from
    ///   the CIDR and sets it.
    /// * If both CIDR (IPv6) and fallback (IPv4) are provided, it assigns a
    ///   local IPv6 address from the CIDR and sets both IPv4 and IPv6
    ///   addresses.
    /// * If only CIDR (IPv6) is provided, it assigns a local IPv6 address from
    ///   the CIDR and sets it.
    /// * If no CIDR is provided but a fallback IP is present, it sets the
    ///   fallback IP address.
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
                let v4 = assign_ipv4_from_extension(&cidr, &extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V4(cidr)), None) => {
                let v4 = assign_ipv4_from_extension(&cidr, &extension);
                connector.set_local_address(Some(v4.into()));
            }
            (Some(IpCidr::V6(cidr)), Some(IpAddr::V4(v4))) => {
                let v6 = assign_ipv6_from_extension(&cidr, &extension);
                connector.set_local_addresses(v4, v6);
            }
            (Some(IpCidr::V6(cidr)), None) => {
                let v6 = assign_ipv6_from_extension(&cidr, &extension);
                connector.set_local_address(Some(v6.into()));
            }
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
    pub async fn try_connect_with_addrs(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        extension: Extensions,
    ) -> std::io::Result<TcpStream> {
        let mut last_err = None;

        for target_addr in addrs {
            match self.try_connect(target_addr, &extension).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            };
        }

        Err(error(last_err))
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
    pub async fn try_connect_with_domain(
        &self,
        host: (String, u16),
        extension: Extensions,
    ) -> std::io::Result<TcpStream> {
        let addrs = lookup_host(host).await?;
        self.try_connect_with_addrs(addrs, extension).await
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
    pub async fn try_connect(
        &self,
        target_addr: SocketAddr,
        extension: &Extensions,
    ) -> std::io::Result<TcpStream> {
        match extension {
            Extensions::Http2Socks5(host, auth) => {
                timeout(
                    self.connect_timeout,
                    try_connect_to_socks5(target_addr, host, auth),
                )
                .await?
            }

            Extensions::None | Extensions::Session(_) => match (self.cidr, self.fallback) {
                (None, Some(fallback)) => {
                    timeout(
                        self.connect_timeout,
                        try_connect_with_addr(target_addr, fallback),
                    )
                    .await?
                }
                (Some(cidr), None) => {
                    timeout(
                        self.connect_timeout,
                        try_connect_with_cidr(target_addr, cidr, &extension),
                    )
                    .await?
                }
                (Some(cidr), Some(fallback)) => {
                    timeout(
                        self.connect_timeout,
                        try_connect_with_cidr_and_fallback(target_addr, cidr, fallback, &extension),
                    )
                    .await?
                }
                _ => timeout(self.connect_timeout, TcpStream::connect(target_addr)).await?,
            },
        }
        .and_then(|stream| {
            tracing::info!("connect {} via {}", target_addr, stream.local_addr()?);
            Ok(stream)
        })
    }
}

/// Attempts to establish a TCP connection to the target SOCKS5 proxy and then
/// to the target address.
///
/// This function takes a `SocketAddr` for the target address and a `Url` for
/// the SOCKS5 proxy. It resolves the host of the SOCKS5 proxy to a list of IP
/// addresses and then attempts to connect to each IP address in turn.
/// If a connection to the SOCKS5 proxy is established, it sends a CONNECT
/// command to the proxy to establish a connection to the target address. If the
/// connection to the target address is successful, it returns the connected
/// `TcpStream`.
///
/// If all connection attempts fail, it returns the last error encountered. If
/// no connection attempts were made because the host could not be resolved to
/// any IP addresses, it returns a `ConnectionAborted` error.
///
/// # Arguments
///
/// * `target_addr` - The target address to connect to.
/// * `url` - The URL of the SOCKS5 proxy.
///
/// # Returns
///
/// This function returns a `std::io::Result<TcpStream>`. If a connection is
/// successfully established, it returns `Ok(stream)`. If there is an error at
/// any step, it returns the error in the `Result`.
async fn try_connect_to_socks5(
    target_addr: SocketAddr,
    host: &(String, u16),
    auth: &Option<UsernamePassword>,
) -> std::io::Result<TcpStream> {
    let mut last_err = None;

    let host = (host.0.as_str(), host.1);
    let addrs = lookup_host(host).await?;

    for socket_addr in addrs {
        match TcpStream::connect(socket_addr).await {
            Ok(mut stream) => {
                let connect =
                    socks5::client::connect(&mut stream, target_addr, auth.clone()).await?;
                tracing::info!("http to socks5 connect {socket_addr} via {connect}");
                return Ok(stream);
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    Err(error(last_err))
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
async fn try_connect_with_cidr(
    target_addr: SocketAddr,
    cidr: IpCidr,
    extension: &Extensions,
) -> std::io::Result<TcpStream> {
    let socket = create_socket_with_cidr(cidr, extension).await?;
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
async fn try_connect_with_addr(
    target_addr: SocketAddr,
    fallback: IpAddr,
) -> std::io::Result<TcpStream> {
    let socket = create_socket_with_addr(&fallback)?;
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
async fn try_connect_with_cidr_and_fallback(
    target_addr: SocketAddr,
    cidr: IpCidr,
    fallback: IpAddr,
    extension: &Extensions,
) -> std::io::Result<TcpStream> {
    match try_connect_with_cidr(target_addr, cidr, extension).await {
        Ok(first) => Ok(first),
        Err(err) => {
            tracing::debug!("try connect with ipv6 failed: {}", err);
            try_connect_with_addr(target_addr, fallback).await
        }
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
fn create_socket_with_addr(ip: &IpAddr) -> std::io::Result<TcpSocket> {
    match ip {
        IpAddr::V4(_) => {
            let socket = TcpSocket::new_v4()?;
            let bind_addr = SocketAddr::new(*ip, 0);
            socket.bind(bind_addr)?;
            Ok(socket)
        }
        IpAddr::V6(_) => {
            let socket = TcpSocket::new_v6()?;
            let bind_addr = SocketAddr::new(*ip, 0);
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
    cidr: IpCidr,
    extension: &Extensions,
) -> std::io::Result<TcpSocket> {
    match cidr {
        IpCidr::V4(cidr) => {
            let socket = TcpSocket::new_v4()?;
            let bind = IpAddr::V4(assign_ipv4_from_extension(&cidr, &extension));
            socket.bind(SocketAddr::new(bind, 0))?;
            Ok(socket)
        }
        IpCidr::V6(cidr) => {
            let socket = TcpSocket::new_v6()?;
            let bind = IpAddr::V6(assign_ipv6_from_extension(&cidr, &extension));
            socket.bind(SocketAddr::new(bind, 0))?;
            Ok(socket)
        }
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
fn assign_ipv4_from_extension(cidr: &Ipv4Cidr, extension: &Extensions) -> Ipv4Addr {
    match extension {
        Extensions::Session((a, b)) => {
            let combined = combine(*a, *b);
            // Calculate the subnet mask and apply it to ensure the base_ip is preserved in
            // the non-variable part
            let subnet_mask = !((1u32 << (32 - cidr.network_length())) - 1);
            let base_ip_bits = u32::from(cidr.first_address()) & subnet_mask;
            let capacity = 2u32.pow(32 - cidr.network_length() as u32) - 1;
            let ip_num = base_ip_bits | ((combined as u32) % capacity);
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
fn assign_ipv6_from_extension(cidr: &Ipv6Cidr, extension: &Extensions) -> Ipv6Addr {
    match extension {
        Extensions::Session((a, b)) => {
            let combined = combine(*a, *b);
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

/// Combines two 64-bit integers into a single 128-bit integer.
fn combine(a: u64, b: u64) -> u128 {
    ((a as u128) << 64) | (b as u128)
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
