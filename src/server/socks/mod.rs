mod auth;
mod conn;
mod error;
mod proto;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::{Level, instrument};

use self::{
    auth::AuthAdaptor,
    conn::{
        ClientConnection, IncomingConnection,
        associate::{self, AssociatedUdpSocket, UdpAssociate},
        bind::{self, Bind},
        connect::{self, Connect},
    },
    error::Error,
    proto::{Address, Reply, UdpHeader},
};
use super::{
    Acceptor, Context, Server,
    connect::{Connector, TcpConnector, UdpConnector},
};

/// SOCKS5 acceptor.
#[derive(Clone)]
pub struct Socks5Acceptor {
    auth: Arc<AuthAdaptor>,
    connector: Connector,
}

/// SOCKS5 server.
pub struct Socks5Server {
    listener: TcpListener,
    acceptor: Socks5Acceptor,
}

// ===== impl Socks5Acceptor =====

impl Socks5Acceptor {
    /// Create a new [`Socks5Acceptor`] instance.
    pub fn new(ctx: Context) -> Self {
        let auth = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => AuthAdaptor::password(username, password),
            _ => AuthAdaptor::no(),
        };

        Socks5Acceptor {
            auth: Arc::new(auth),
            connector: ctx.connector,
        }
    }
}

impl Acceptor for Socks5Acceptor {
    async fn accept(self, (stream, socket_addr): (TcpStream, SocketAddr)) {
        if let Err(err) = handle(
            IncomingConnection::new(stream, self.auth),
            socket_addr,
            self.connector,
        )
        .await
        {
            tracing::trace!("[SOCKS5] error: {}", err);
        }
    }
}

// ===== impl Socks5Server =====

impl Socks5Server {
    /// Create a new [`Socks5Server`] instance.
    pub fn new(ctx: Context) -> std::io::Result<Self> {
        let socket = if ctx.bind.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        socket.set_nodelay(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;
        socket.listen(ctx.concurrent).map(|listener| Socks5Server {
            listener,
            acceptor: Socks5Acceptor::new(ctx),
        })
    }
}

impl Server for Socks5Server {
    async fn start(mut self) -> std::io::Result<()> {
        tracing::info!(
            "Socks5 proxy server listening on {}",
            self.listener.local_addr()?
        );

        loop {
            // Accept a new connection
            let conn = Socks5Server::incoming(&mut self.listener).await;
            tokio::spawn(self.acceptor.clone().accept(conn));
        }
    }
}

async fn handle(
    conn: IncomingConnection,
    socket_addr: SocketAddr,
    connector: Connector,
) -> std::io::Result<()> {
    let (mut conn, extension) = conn.authenticate().await?;
    let extension = match extension {
        Ok(extension) => extension,
        Err(err) => {
            tracing::trace!(
                "[SOCKS5] authentication failed: {err}, closing connection from {socket_addr}"
            );
            conn.shutdown().await?;
            return Ok(());
        }
    };

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, address) => {
            handle_udp(associate, address, connector.udp(extension)).await
        }
        ClientConnection::Connect(connect, address) => {
            handle_connect(connect, address, connector.tcp(extension)).await
        }
        ClientConnection::Bind(bind, address) => {
            handle_bind(bind, address, connector.tcp(extension)).await
        }
    }
}

#[instrument(skip(connect, connector), level = Level::DEBUG)]
async fn handle_connect(
    connect: Connect<connect::NeedReply>,
    address: Address,
    connector: TcpConnector<'_>,
) -> std::io::Result<()> {
    let outbound = match address {
        Address::SocketAddress(addr) => connector.connect(addr).await,
        Address::DomainAddress(domain, port) => connector.connect((domain, port)).await,
    };

    match outbound {
        Ok(mut outbound) => {
            let mut inbound = connect
                .reply(Reply::Succeeded, Address::unspecified())
                .await?;

            match crate::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                Ok((from_client, from_server)) => {
                    tracing::info!(
                        "[SOCKS5][CONNECT] client wrote {} bytes and received {} bytes",
                        from_client,
                        from_server
                    );
                }
                Err(err) => {
                    tracing::trace!("[SOCKS5][CONNECT] tunnel error: {}", err);
                }
            };

            outbound.shutdown().await
        }
        Err(err) => {
            let mut conn = connect
                .reply(Reply::HostUnreachable, Address::unspecified())
                .await?;
            conn.shutdown().await?;
            Err(err)
        }
    }
}

const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

#[instrument(skip(associate, connector), level = Level::DEBUG)]
async fn handle_udp(
    associate: UdpAssociate<associate::NeedReply>,
    address: Address,
    connector: UdpConnector<'_>,
) -> std::io::Result<()> {
    const BUF_SIZE: usize = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();

    let socket = UdpSocket::bind(SocketAddr::from((associate.local_addr()?.ip(), 0))).await?;
    let listen_addr = socket.local_addr()?;
    tracing::info!("[SOCKS5][UDP] listening on: {listen_addr}");

    let mut reply_listener = associate
        .reply(Reply::Succeeded, Address::from(listen_addr))
        .await?;

    let inbound = AssociatedUdpSocket::from((socket, BUF_SIZE));
    let (preferred_outbound, fallback_outbound) = connector.create_socket_dual_stack().await?;

    // Determine the source IP for UDP packets:
    // If the client does not explicitly specify IP limits in the UDP association request,
    // default to limiting access to the same source IP as the TCP.
    let src_ip = match address {
        Address::SocketAddress(addr) if !addr.ip().is_unspecified() => addr.ip(),
        // For all other cases (including unspecified IPs, domain names, or invalid addresses),
        // default to only allowing the IP address of the TCP control connection.
        // See: RFC 1928 Section 7 - https://datatracker.ietf.org/doc/html/rfc1928#section-7
        _ => reply_listener.peer_addr()?.ip(),
    };
    let src_port = AtomicU16::new(0);

    loop {
        let result = tokio::select! {
            req = async {
                inbound.set_max_packet_size(BUF_SIZE);
                let (pkt, frag, dst_addr, src_addr) = inbound.recv_from().await?;

                if frag != 0 {
                    return Err(Error::from("[SOCKS5][UDP] packet fragment is not supported"));
                }

                // Check if the source IP matches, considering IPv4-mapped IPv6 addresses
                let is_authorized = match (src_addr.ip(), src_ip) {
                    // Direct match
                    (src, expected) if src == expected => true,

                    // IPv4-mapped IPv6 to IPv4 match
                    (std::net::IpAddr::V4(src_v4), std::net::IpAddr::V6(expected_v6)) => {
                        expected_v6.to_ipv4_mapped() == Some(src_v4)
                    }

                    // IPv4 to IPv4-mapped IPv6 match
                    (std::net::IpAddr::V6(src_v6), std::net::IpAddr::V4(expected_v4)) => {
                        src_v6.to_ipv4_mapped() == Some(expected_v4)
                    }

                    _ => false,
                };

                if !is_authorized {
                    tracing::trace!(
                        "[SOCKS5][UDP] packet from unauthorized IP: {}, expected: {}. Dropped.",
                        src_addr.ip(),
                        src_ip
                    );

                    return Err(Error::from(format!(
                        "[SOCKS5][UDP] unauthorized IP: {}, expected: {}",
                        src_addr.ip(),
                        src_ip
                    )));
                }

                src_port.store(src_addr.port(), Ordering::Relaxed);

                tracing::info!(
                    "[SOCKS5][UDP] {src_addr} -> {dst_addr} incoming packet size {}",
                    pkt.len()
                );

                match dst_addr {
                    Address::SocketAddress(target_addr) => {
                        connector
                            .send_packet(&pkt, target_addr, &preferred_outbound, fallback_outbound.as_ref())
                            .await?;
                    }
                    Address::DomainAddress(domain, port) => {
                        connector
                            .send_packet(&pkt, (domain, port), &preferred_outbound, fallback_outbound.as_ref())
                            .await?;
                    }
                }

                Ok(())
            } => req,

            resp_primary = async {
                let mut buf = [0u8; MAX_UDP_RELAY_PACKET_SIZE];
            let (len, remote_addr) = preferred_outbound.recv_from(&mut buf).await?;
                let src_addr = SocketAddr::new(src_ip, src_port.load(Ordering::Relaxed));

                tracing::info!("[SOCKS5][UDP] {src_addr} <- {remote_addr} feedback to incoming, packet size {len}");

                inbound
                    .send_to(&buf[..len], 0, remote_addr.into(), src_addr)
                    .await
                    .map(|_| ())
                    .map_err(Error::from)
            } => resp_primary,

            resp_secondary = async {
                if let Some(secondary) = &fallback_outbound {
                    let mut buf = [0u8; MAX_UDP_RELAY_PACKET_SIZE];
                    let (len, remote_addr) = secondary.recv_from(&mut buf).await?;
                    let src_addr = SocketAddr::new(src_ip, src_port.load(Ordering::Relaxed));

                    tracing::info!("[SOCKS5][UDP] {src_addr} <- {remote_addr} feedback to incoming, packet size {len}");

                    inbound
                        .send_to(&buf[..len], 0, remote_addr.into(), src_addr)
                        .await
                        .map(|_| ())
                        .map_err(Error::from)
                } else {
                    // If there's no secondary socket, just await forever.
                    futures_util::future::pending().await
                }
            } => resp_secondary,

            _ = reply_listener.wait_until_closed() => {
                break;
            }
        };

        if let Err(err) = result {
            tracing::trace!("[SOCKS5][UDP] proxy error: {err}");
        }
    }

    reply_listener.shutdown().await?;
    tracing::info!("[SOCKS5][UDP] {listen_addr} listener closed");
    Ok(())
}

/// Handles the SOCKS5 BIND command, which is used to listen for inbound connections.
/// This is typically used in server mode applications, such as FTP passive mode.
///
/// ### Workflow
///
/// 1. **Client sends BIND request**
///    - Client sends a BIND request to the SOCKS5 proxy server.
///    - Proxy server responds with an IP address and port, which is the temporary listening port
///      allocated by the proxy server.
///
/// 2. **Proxy server listens for inbound connections**
///    - Proxy server listens on the allocated temporary port.
///    - Proxy server sends a BIND response to the client, notifying the listening address and port.
///
/// 3. **Client receives BIND response**
///    - Client receives the BIND response from the proxy server, knowing the address and port the
///      proxy server is listening on.
///
/// 4. **Target server initiates connection**
///    - Target server initiates a connection to the proxy server's listening address and port.
///
/// 5. **Proxy server accepts inbound connection**
///    - Proxy server accepts the inbound connection from the target server.
///    - Proxy server sends a second BIND response to the client, notifying that the inbound
///      connection has been established.
///
/// 6. **Client receives second BIND response**
///    - Client receives the second BIND response from the proxy server, knowing that the inbound
///      connection has been established.
///
/// 7. **Data transfer**
///    - Proxy server forwards data between the client and the target server.
///
/// ### Text Flowchart
///
/// ```plaintext
/// Client                Proxy Server                Target Server
///   |                        |                        |
///   |----BIND request------->|                        |
///   |                        |                        |
///   |                        |<---Allocate port-------|
///   |                        |                        |
///   |<---BIND response-------|                        |
///   |                        |                        |
///   |                        |<---Target connects-----|
///   |                        |                        |
///   |                        |----Second BIND response>|
///   |                        |                        |
///   |<---Second BIND response|                        |
///   |                        |                        |
///   |----Data transfer------>|----Forward data------->|
///   |<---Data transfer-------|<---Forward data--------|
///   |                        |                        |
/// ```
#[instrument(skip(bind, _address, connector), level = Level::DEBUG)]
async fn handle_bind(
    bind: Bind<bind::NeedFirstReply>,
    _address: Address,
    connector: TcpConnector<'_>,
) -> std::io::Result<()> {
    let listen_ip = connector.socket_addr(|| bind.local_addr().map(|socket| socket.ip()))?;
    let listener = TcpListener::bind(listen_ip).await?;
    tracing::info!("[SOCKS5][BIND] listening on {}", listener.local_addr()?);

    let inbound = bind
        .reply(Reply::Succeeded, Address::from(listener.local_addr()?))
        .await?;

    let (mut outbound, outbound_addr) = listener.accept().await?;
    tracing::info!("[SOCKS5][BIND] accepted connection from {}", outbound_addr);

    match inbound
        .reply(Reply::Succeeded, Address::from(outbound_addr))
        .await
    {
        Ok(mut inbound) => {
            match crate::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                Ok((from_client, from_server)) => {
                    tracing::info!(
                        "[SOCKS5][BIND] client wrote {} bytes and received {} bytes",
                        from_client,
                        from_server
                    );
                }
                Err(err) => {
                    tracing::trace!("[SOCKS5][BIND] tunnel error: {}", err);
                }
            }
            inbound.shutdown().await?;
            outbound.shutdown().await?;
            Ok(())
        }
        Err((err, mut tcp)) => {
            tcp.shutdown().await?;
            return Err(err);
        }
    }
}
