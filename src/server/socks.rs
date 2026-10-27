mod auth;
mod conn;
mod error;
mod proto;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::BytesMut;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
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
use super::{Acceptor, Context, Handle, Server, drain_connections, io};
use crate::connect::{Connector, TcpConnector, UdpConnector};
#[cfg(feature = "management")]
use crate::{
    server::auth::Authenticated,
    traffic::{Direction, Io, Meter},
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
    limit: Arc<Semaphore>,
    acceptor: Socks5Acceptor,
}

// ===== impl Socks5Acceptor =====

impl Socks5Acceptor {
    /// Create a new [`Socks5Acceptor`] instance.
    pub fn new(ctx: Context) -> Self {
        let auth = AuthAdaptor::from_source(ctx.auth);

        Socks5Acceptor {
            auth: Arc::new(auth),
            connector: ctx.connector,
        }
    }
}

impl Acceptor for Socks5Acceptor {
    async fn accept(self, (stream, socket_addr): (TcpStream, SocketAddr), _handle: Handle) {
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
    /// Inspect the bound socket for fixtures that request port zero.
    #[cfg(test)]
    pub(super) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Create a new [`Socks5Server`] instance.
    pub fn new(ctx: Context) -> std::io::Result<Self> {
        let limit = super::connection_limit(ctx.concurrent)?;
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
            limit,
            acceptor: Socks5Acceptor::new(ctx),
        })
    }
}

impl Server for Socks5Server {
    async fn start(mut self, handle: Handle) -> std::io::Result<()> {
        tracing::info!(
            "Socks5 proxy server listening on {}",
            self.listener.local_addr()?
        );
        let mut connections = tokio::task::JoinSet::new();

        let result = loop {
            tokio::select! {
                biased;
                _ = handle.wait_graceful_shutdown() => break Ok(()),
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        break Err(std::io::Error::other(error));
                    }
                }
                conn = Socks5Server::incoming(&mut self.listener, &self.limit) => {
                    let (conn, permit) = match conn {
                        Ok(conn) => conn,
                        Err(error) => break Err(error),
                    };
                    let acceptor = self.acceptor.clone();
                    let connection_handle = handle.clone();
                    connections.spawn_on(async move {
                        // Includes authentication, BIND waiting and the entire
                        // UDP association, not just its first reply.
                        let _permit = permit;
                        acceptor.accept(conn, connection_handle).await;
                    }, handle.runtime_handle());
                }
            }
        };
        // Refuse new TCP sessions before waiting on CONNECT/BIND or the TCP
        // control connection that owns a UDP association (RFC 1928 §6).
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
        drop(self.listener);
        if result.is_err() {
            handle.request_graceful_shutdown();
        }
        let drained = drain_connections(&mut connections, "SOCKS5", &handle).await;
        result.and(drained)
    }
}

async fn handle(
    conn: IncomingConnection,
    socket_addr: SocketAddr,
    connector: Connector,
) -> std::io::Result<()> {
    let (conn, authenticated) = match conn.authenticate().await {
        Ok(authenticated) => authenticated,
        Err(error) => {
            if error.is_rejected() {
                tracing::trace!("[SOCKS5] authentication failed for {socket_addr}: {error}");
                return Ok(());
            }
            return Err(error.into_io_error());
        }
    };

    let extension = authenticated.extension;
    let connector = connector.with_source(authenticated.source);
    let result = match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, address) => {
            if authenticated.explicit_preset() {
                // The command is implemented, but this TCP-only request is
                // denied by policy (RFC 1928 section 6, REP 0x02).
                // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
                associate
                    .reject(Reply::ConnectionNotAllowed, Address::unspecified())
                    .await?;
                return Ok(());
            }
            handle_udp(
                associate,
                address,
                connector.udp(extension),
                #[cfg(feature = "management")]
                &authenticated,
            )
            .await
        }
        ClientConnection::Connect(connect, address) => {
            let extension = match authenticated.tcp_extension() {
                Ok(extension) => extension,
                Err(_) => {
                    connect
                        .reject(Reply::ConnectionNotAllowed, Address::unspecified())
                        .await?;
                    return Ok(());
                }
            };
            if connector.require_profile(extension).is_err() {
                // Backend availability is a local implementation failure, not
                // an invented peer protocol error or a silent native retry.
                connect
                    .reject(Reply::GeneralFailure, Address::unspecified())
                    .await?;
                return Ok(());
            }
            handle_connect(
                connect,
                address,
                connector.tcp(extension),
                #[cfg(feature = "management")]
                &authenticated,
            )
            .await
        }
        ClientConnection::Bind(bind, address) => {
            if authenticated.explicit_preset() {
                bind.reject(Reply::ConnectionNotAllowed, Address::unspecified())
                    .await?;
                return Ok(());
            }
            handle_bind(
                bind,
                address,
                connector.tcp(extension),
                #[cfg(feature = "management")]
                &authenticated,
            )
            .await
        }
    };
    // BIND's wait and the complete UDP association belong to this admission,
    // not just the authentication handshake or its first successful reply.
    #[cfg(feature = "management")]
    drop(authenticated);
    result
}

#[instrument(skip_all, fields(?address), level = Level::DEBUG)]
async fn handle_connect(
    connect: Connect<connect::NeedReply>,
    address: Address,
    connector: TcpConnector<'_>,
    #[cfg(feature = "management")] authenticated: &Authenticated,
) -> std::io::Result<()> {
    let outbound = match address {
        Address::SocketAddress(addr) => {
            tracing::info!("[SOCKS5][CONNECT] forwarding connection to {addr}");
            connector.connect(addr).await
        }
        Address::DomainAddress(domain, port) => {
            tracing::info!("[SOCKS5][CONNECT] forwarding connection to {domain}:{port}");
            connector.connect((domain, port)).await
        }
    };

    match outbound {
        Ok(mut outbound) => {
            let bound_addr = match outbound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    connect
                        .reject(reply_for_connect_error(&error), Address::unspecified())
                        .await?;
                    return Err(error);
                }
            };
            let mut inbound = connect.succeed(Address::from(bound_addr)).await?;
            // The SOCKS reply is outside the payload writer. Both codec
            // pre-read bytes and later copy writes use the same accepted-byte
            // boundary, including partial progress before an error or cancel.
            #[cfg(feature = "management")]
            let mut outbound = Io::new(&mut outbound, authenticated.meter(Direction::Upload));
            {
                let pending = inbound.take_pending_data();
                if !pending.is_empty() {
                    outbound.write_all(&pending).await?;
                }
            }

            let inbound = inbound.transport_mut()?;
            #[cfg(feature = "management")]
            let mut inbound = Io::new(inbound, authenticated.meter(Direction::Download));
            #[cfg(feature = "management")]
            let inbound = &mut inbound;
            match io::copy_bidirectional(inbound, &mut outbound).await {
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
            let reply = reply_for_connect_error(&err);
            connect.reject(reply, Address::unspecified()).await?;
            Err(err)
        }
    }
}

fn reply_for_connect_error(error: &std::io::Error) -> Reply {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Reply::ConnectionNotAllowed,
        std::io::ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
        std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::AddrNotAvailable => {
            Reply::HostUnreachable
        }
        std::io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
        _ => Reply::GeneralFailure,
    }
}

// The UDP length field is 16 bits. A buffer of this size therefore holds every
// ordinary datagram representable by that field without truncation.
// https://www.rfc-editor.org/rfc/rfc768.html
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;
const MAX_BIND_EARLY_DATA: usize = 64 * 1024;

#[instrument(skip_all, fields(?address), level = Level::DEBUG)]
async fn handle_udp(
    associate: UdpAssociate<associate::NeedReply>,
    address: Address,
    connector: UdpConnector<'_>,
    #[cfg(feature = "management")] authenticated: &Authenticated,
) -> std::io::Result<()> {
    let local_ip = match associate.local_addr() {
        Ok(address) => address.ip(),
        Err(error) => {
            associate
                .reject(reply_for_connect_error(&error), Address::unspecified())
                .await?;
            return Err(error);
        }
    };
    let src_ip = match address {
        Address::SocketAddress(address) if !address.ip().is_unspecified() => address.ip(),
        _ => match associate.peer_addr() {
            Ok(address) => address.ip(),
            Err(error) => {
                associate
                    .reject(reply_for_connect_error(&error), Address::unspecified())
                    .await?;
                return Err(error);
            }
        },
    };
    let socket = match UdpSocket::bind(SocketAddr::from((local_ip, 0))).await {
        Ok(socket) => socket,
        Err(error) => {
            let reply = reply_for_connect_error(&error);
            associate.reject(reply, Address::unspecified()).await?;
            return Err(error);
        }
    };
    let listen_addr = match socket.local_addr() {
        Ok(address) => address,
        Err(error) => {
            let reply = reply_for_connect_error(&error);
            associate.reject(reply, Address::unspecified()).await?;
            return Err(error);
        }
    };
    let inbound = AssociatedUdpSocket::new(socket);
    let (preferred_outbound, fallback_outbound) = match connector.create_socket_dual_stack().await {
        Ok(sockets) => sockets,
        Err(error) => {
            let reply = reply_for_connect_error(&error);
            associate.reject(reply, Address::unspecified()).await?;
            return Err(error);
        }
    };
    let mut reply_listener = associate.succeed(Address::from(listen_addr)).await?;
    tracing::info!("[SOCKS5][UDP] listening on: {listen_addr}");

    // If the request does not identify a source IP, limit the association to
    // the TCP control peer. RFC 1928 permits the request address to be used as
    // an additional access restriction and requires all other source IPs to be
    // dropped.
    // https://www.rfc-editor.org/rfc/rfc1928.html#section-7
    let mut src_port = 0;
    let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM_SIZE];
    let mut response_buffer = BytesMut::new();
    #[cfg(feature = "management")]
    let upload = authenticated.meter(Direction::Upload);
    #[cfg(feature = "management")]
    let download = authenticated.meter(Direction::Download);

    loop {
        let ready = tokio::select! {
            ready = inbound.as_ref().readable() => Some((UdpReady::Client, ready)),
            ready = preferred_outbound.readable() => Some((UdpReady::Preferred, ready)),
            ready = async {
                match fallback_outbound.as_ref() {
                    Some(socket) => socket.readable().await,
                    None => futures_util::future::pending().await,
                }
            } => Some((UdpReady::Fallback, ready)),
            _ = reply_listener.wait_until_closed(&mut buffer) => {
                None
            }
        };
        let Some((ready, readiness)) = ready else {
            break;
        };
        readiness?;

        let result = match ready {
            UdpReady::Client => {
                forward_udp_request(
                    &inbound,
                    &mut buffer,
                    src_ip,
                    &mut src_port,
                    &connector,
                    (&preferred_outbound, fallback_outbound.as_ref()),
                    #[cfg(feature = "management")]
                    upload.as_ref(),
                )
                .await
            }
            UdpReady::Preferred => {
                forward_udp_response(
                    &inbound,
                    &preferred_outbound,
                    &mut buffer,
                    &mut response_buffer,
                    src_ip,
                    src_port,
                    #[cfg(feature = "management")]
                    download.as_ref(),
                )
                .await
            }
            UdpReady::Fallback => {
                let Some(fallback) = fallback_outbound.as_ref() else {
                    continue;
                };
                forward_udp_response(
                    &inbound,
                    fallback,
                    &mut buffer,
                    &mut response_buffer,
                    src_ip,
                    src_port,
                    #[cfg(feature = "management")]
                    download.as_ref(),
                )
                .await
            }
        };

        if let Err(error) = result {
            tracing::trace!("[SOCKS5][UDP] proxy error: {error}");
        }
    }

    reply_listener.shutdown().await?;
    tracing::info!("[SOCKS5][UDP] {listen_addr} listener closed");
    Ok(())
}

#[derive(Clone, Copy)]
enum UdpReady {
    Client,
    Preferred,
    Fallback,
}

async fn forward_udp_request(
    inbound: &AssociatedUdpSocket,
    buffer: &mut [u8],
    expected_ip: IpAddr,
    client_port: &mut u16,
    connector: &UdpConnector<'_>,
    outbound: (&UdpSocket, Option<&UdpSocket>),
    #[cfg(feature = "management")] meter: Option<&Meter>,
) -> Result<(), Error> {
    let (len, source) = match inbound.as_ref().try_recv_from(buffer) {
        Ok(packet) => packet,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !ip_addresses_match(source.ip(), expected_ip) {
        tracing::trace!(
            "[SOCKS5][UDP] packet from unauthorized IP: {}, expected: {}. Dropped.",
            source.ip(),
            expected_ip
        );
        return Ok(());
    }
    let (header, header_len) = match UdpHeader::decode(&buffer[..len]) {
        Ok(header) => header,
        // RFC 1928 section 7 requires malformed or unsupported datagrams to be
        // dropped without sending an error to the client.
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-7
        Err(_) => return Ok(()),
    };
    if header.frag != 0 {
        return Ok(());
    }

    *client_port = source.port();
    let packet = &buffer[header_len..len];
    let (preferred_outbound, fallback_outbound) = outbound;
    let _sent = match header.address {
        Address::SocketAddress(target) => {
            tracing::trace!(
                "[SOCKS5][UDP] {source} -> {target} forwarding packet, size {}",
                packet.len()
            );
            connector
                .send_packet(packet, target, preferred_outbound, fallback_outbound)
                .await?
        }
        Address::DomainAddress(domain, port) => {
            tracing::trace!(
                "[SOCKS5][UDP] {source} -> {domain}:{port} forwarding packet, size {}",
                packet.len()
            );
            connector
                .send_packet(
                    packet,
                    (domain, port),
                    preferred_outbound,
                    fallback_outbound,
                )
                .await?
        }
    };
    // A UDP send accepts an entire datagram or fails. Keep the original error
    // behavior, but never interpret a short/unknown return as a complete packet.
    // Only DATA is payload; the RFC 1928 section 7 relay header is excluded.
    #[cfg(feature = "management")]
    if _sent == packet.len()
        && let Some(meter) = meter
    {
        meter.add(packet.len());
    }
    Ok(())
}

async fn forward_udp_response(
    inbound: &AssociatedUdpSocket,
    outbound: &UdpSocket,
    buffer: &mut [u8],
    response_buffer: &mut BytesMut,
    client_ip: IpAddr,
    client_port: u16,
    #[cfg(feature = "management")] meter: Option<&Meter>,
) -> Result<(), Error> {
    let (len, remote) = match outbound.try_recv_from(buffer) {
        Ok(packet) => packet,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if client_port == 0 {
        return Ok(());
    }
    let client = SocketAddr::new(client_ip, client_port);
    tracing::trace!("[SOCKS5][UDP] {client} <- {remote} feedback to incoming, packet size {len}");
    let _sent = inbound
        .send_to_buffered(&buffer[..len], 0, remote.into(), client, response_buffer)
        .await?;
    // send_to_buffered already subtracts the SOCKS header from its result.
    // Failed/oversized responses and packets without a client port add nothing.
    #[cfg(feature = "management")]
    if _sent == len
        && let Some(meter) = meter
    {
        meter.add(len);
    }
    Ok(())
}

/// Compares IP addresses after normalizing the IPv4-mapped IPv6 representation
/// defined by RFC 4291 section 2.5.5.2.
/// https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.5.2
fn ip_addresses_match(left: IpAddr, right: IpAddr) -> bool {
    fn normalize(address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address => address,
        }
    }

    normalize(left) == normalize(right)
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
#[instrument(skip_all, level = Level::DEBUG)]
async fn handle_bind(
    bind: Bind<bind::NeedFirstReply>,
    address: Address,
    connector: TcpConnector<'_>,
    #[cfg(feature = "management")] authenticated: &Authenticated,
) -> std::io::Result<()> {
    let listen_ip = match connector.socket_addr(|| bind.local_addr().map(|socket| socket.ip())) {
        Ok(address) => address,
        Err(error) => {
            bind.reject(reply_for_connect_error(&error), Address::unspecified())
                .await?;
            return Err(error);
        }
    };
    let listener = match TcpListener::bind(listen_ip).await {
        Ok(listener) => listener,
        Err(error) => {
            bind.reject(reply_for_connect_error(&error), Address::unspecified())
                .await?;
            return Err(error);
        }
    };
    let listen_addr = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            bind.reject(reply_for_connect_error(&error), Address::unspecified())
                .await?;
            return Err(error);
        }
    };
    tracing::info!("[SOCKS5][BIND] listening on {listen_addr}");

    let mut inbound = bind.succeed(Address::from(listen_addr)).await?;
    if inbound.pending_len() > MAX_BIND_EARLY_DATA {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 BIND client sent too much data before the second reply",
        );
        inbound
            .reject(Reply::GeneralFailure, Address::unspecified())
            .await?;
        return Err(error);
    }
    let mut early_data = BytesMut::new();
    let mut early_buffer = [0_u8; 8192];

    // RFC 1928 keeps the first BIND TCP connection open while the proxy waits
    // for the peer. Monitor it alongside accept() so a disconnected client
    // releases the temporary listener promptly. Preserve data received before
    // the second reply, with a limit so an untrusted peer cannot grow memory
    // without bound while the rendezvous is pending.
    // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
    let accepted = loop {
        tokio::select! {
            accepted = listener.accept() => break accepted,
            read = inbound.read_early_data(&mut early_buffer) => match read {
                Ok(0) => return Ok(()),
                Ok(len) => {
                    let buffered_len = inbound
                        .pending_len()
                        .checked_add(early_data.len())
                        .and_then(|buffered| buffered.checked_add(len))
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "SOCKS5 BIND early data length overflow",
                            )
                        })?;
                    if buffered_len > MAX_BIND_EARLY_DATA {
                        let error = std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SOCKS5 BIND client sent too much data before the second reply",
                        );
                        inbound
                            .reject(Reply::GeneralFailure, Address::unspecified())
                            .await?;
                        return Err(error);
                    }
                    early_data.extend_from_slice(&early_buffer[..len]);
                }
                Err(error) => return Err(error),
            }
        }
    };
    let (mut outbound, outbound_addr) = match accepted {
        Ok(connection) => connection,
        Err(error) => {
            inbound
                .reject(reply_for_connect_error(&error), Address::unspecified())
                .await?;
            return Err(error);
        }
    };
    tracing::info!("[SOCKS5][BIND] accepted connection from {}", outbound_addr);

    let peer_error = match bind_peer_matches(&address, outbound_addr).await {
        Ok(true) => None,
        Ok(false) => Some((
            Reply::ConnectionNotAllowed,
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SOCKS5 BIND rejected unexpected peer {outbound_addr}"),
            ),
        )),
        Err(error) => Some((Reply::HostUnreachable, error)),
    };

    if let Some((reply, error)) = peer_error {
        // RFC 1928 section 6 requires a second BIND reply after the inbound
        // connection succeeds or fails.
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-6
        let reply_result = inbound.reject(reply, Address::from(outbound_addr)).await;
        let outbound_shutdown = outbound.shutdown().await;
        reply_result?;
        outbound_shutdown?;
        return Err(error);
    }

    match inbound.succeed(Address::from(outbound_addr)).await {
        Ok(mut inbound) => {
            // Neither BIND reply nor data merely buffered while waiting for
            // the peer is traffic. Count only successful writes after reply 2.
            #[cfg(feature = "management")]
            let mut outbound = Io::new(&mut outbound, authenticated.meter(Direction::Upload));
            {
                let pending = inbound.take_pending_data();
                if !pending.is_empty() {
                    outbound.write_all(&pending).await?;
                }
            }
            if !early_data.is_empty() {
                outbound.write_all(&early_data).await?;
            }
            drop(early_data);
            let copied = {
                let inbound = inbound.transport_mut()?;
                #[cfg(feature = "management")]
                let mut inbound = Io::new(inbound, authenticated.meter(Direction::Download));
                #[cfg(feature = "management")]
                let inbound = &mut inbound;
                io::copy_bidirectional(inbound, &mut outbound).await
            };
            match copied {
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
        Err((err, mut inbound)) => {
            inbound.shutdown().await?;
            Err(err)
        }
    }
}

async fn bind_peer_matches(expected: &Address, actual: SocketAddr) -> std::io::Result<bool> {
    match expected {
        Address::SocketAddress(expected) => {
            let ip_matches =
                expected.ip().is_unspecified() || ip_addresses_match(expected.ip(), actual.ip());
            let port_matches = expected.port() == 0 || expected.port() == actual.port();
            Ok(ip_matches && port_matches)
        }
        Address::DomainAddress(domain, port) => {
            let mut addresses = tokio::net::lookup_host((domain.as_str(), *port)).await?;
            Ok(addresses.any(|expected| {
                ip_addresses_match(expected.ip(), actual.ip())
                    && (expected.port() == 0 || expected.port() == actual.port())
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpSocket, UdpSocket},
        task::JoinSet,
    };

    use super::*;
    use crate::server::socks::proto::{StreamOperation, UdpHeader};

    fn test_connector() -> Connector {
        Connector::new(
            None,
            None,
            None,
            5,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            None,
        )
    }

    async fn start_socks5_connection() -> (TcpStream, tokio::task::JoinHandle<std::io::Result<()>>)
    {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await?;
            handle(
                IncomingConnection::new(stream, Arc::new(AuthAdaptor::no())),
                peer,
                test_connector(),
            )
            .await
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);
        (client, server)
    }

    fn socks5_request(command: u8, address: &Address) -> Vec<u8> {
        let mut request = Vec::with_capacity(3 + address.len());
        request.extend_from_slice(&[0x05, command, 0x00]);
        address.write_to_buf(&mut request).unwrap();
        request
    }

    async fn write_socks5_request(client: &mut TcpStream, command: u8, address: &Address) {
        let request = socks5_request(command, address);
        client.write_all(&request).await.unwrap();
    }

    async fn write_bind_request(client: &mut TcpStream, address: &Address) {
        write_socks5_request(client, 0x02, address).await;
    }

    async fn write_udp_associate_request(client: &mut TcpStream, address: &Address) {
        write_socks5_request(client, 0x03, address).await;
    }

    fn udp_relay_packet(frag: u8, address: Address, payload: &[u8]) -> Vec<u8> {
        let header = UdpHeader::new(frag, address);
        let mut packet = Vec::with_capacity(header.len() + payload.len());
        header.write_to_buf(&mut packet).unwrap();
        packet.extend_from_slice(payload);
        packet
    }

    async fn assert_udp_relay_response(
        client: &UdpSocket,
        relay_address: SocketAddr,
        expected_address: Address,
        expected_payload: &[u8],
    ) {
        let mut packet = vec![0; MAX_UDP_DATAGRAM_SIZE];
        let (len, source) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, relay_address);

        let (header, header_len) = UdpHeader::decode(&packet[..len]).unwrap();
        assert_eq!(header.frag, 0);
        assert_eq!(header.address, expected_address);
        assert_eq!(&packet[header_len..len], expected_payload);
    }

    async fn assert_udp_associate_round_trip(datagram_len: usize) {
        let echo = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let echo_address = echo.local_addr().unwrap();
        let header = UdpHeader::new(0, Address::from(echo_address));
        let payload = vec![0x5a; datagram_len.checked_sub(header.len()).unwrap()];
        let expected_payload = payload.clone();
        let echo_task = tokio::spawn(async move {
            let mut packet = vec![0; MAX_UDP_DATAGRAM_SIZE];
            let (len, peer) = echo.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..len], expected_payload.as_slice());
            echo.send_to(&packet[..len], peer).await.unwrap();
        });

        let client_udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let client_udp_address = client_udp.local_addr().unwrap();
        let (mut control, server) = start_socks5_connection().await;

        write_udp_associate_request(&mut control, &Address::from(client_udp_address)).await;
        let (reply, relay_address) = read_socks5_reply(&mut control).await;
        assert_eq!(reply, Reply::Succeeded);
        let Address::SocketAddress(relay_address) = relay_address else {
            panic!("UDP ASSOCIATE reply did not contain a socket address");
        };

        let request = udp_relay_packet(0, Address::from(echo_address), &payload);
        client_udp.send_to(&request, relay_address).await.unwrap();
        assert_udp_relay_response(
            &client_udp,
            relay_address,
            Address::from(echo_address),
            &payload,
        )
        .await;

        echo_task.await.unwrap();
        control.shutdown().await.unwrap();
        server.await.unwrap().unwrap();
    }

    async fn read_socks5_reply(client: &mut TcpStream) -> (Reply, Address) {
        let mut header = [0; 4];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x05);
        assert_eq!(header[2], 0x00);

        let mut address = vec![header[3]];
        match header[3] {
            0x01 => {
                let mut body = [0; 6];
                client.read_exact(&mut body).await.unwrap();
                address.extend_from_slice(&body);
            }
            0x03 => {
                let mut length = [0];
                client.read_exact(&mut length).await.unwrap();
                address.push(length[0]);
                let mut body = vec![0; usize::from(length[0]) + 2];
                client.read_exact(&mut body).await.unwrap();
                address.extend_from_slice(&body);
            }
            0x04 => {
                let mut body = [0; 18];
                client.read_exact(&mut body).await.unwrap();
                address.extend_from_slice(&body);
            }
            address_type => panic!("unexpected SOCKS5 address type {address_type:#x}"),
        }

        (
            Reply::try_from(header[1]).unwrap(),
            Address::try_from(address).unwrap(),
        )
    }

    async fn run_reqwest_interop(
        proxy_scheme: &str,
        target_host: &str,
        auth: AuthAdaptor,
        credentials: Option<(&str, &str)>,
        selected_source: bool,
    ) {
        const REQUESTS: usize = 32;

        let target_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_task = tokio::spawn(async move {
            loop {
                let (mut stream, peer) = target_listener.accept().await.unwrap();
                if selected_source {
                    assert_eq!(peer.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
                }
                tokio::spawn(async move {
                    let mut request = Vec::with_capacity(512);
                    loop {
                        let mut chunk = [0; 512];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .unwrap();
                });
            }
        });

        let proxy_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let connector = if selected_source {
            Connector::new(
                Some("192.0.2.1/32".parse().unwrap()),
                None,
                None,
                3,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            )
        } else {
            test_connector()
        };
        let auth = Arc::new(auth);
        let proxy_task = tokio::spawn(async move {
            loop {
                let (stream, peer) = proxy_listener.accept().await.unwrap();
                let auth = Arc::clone(&auth);
                let connector = connector.clone();
                tokio::spawn(async move {
                    handle(IncomingConnection::new(stream, auth), peer, connector)
                        .await
                        .unwrap();
                });
            }
        });

        let proxy_url = match credentials {
            Some((username, password)) => {
                format!("{proxy_scheme}://{username}:{password}@{proxy_addr}")
            }
            None => format!("{proxy_scheme}://{proxy_addr}"),
        };
        let client = crate::oneself::test_http_client_builder()
            .unwrap()
            .proxy(reqwest::Proxy::all(proxy_url).unwrap())
            .pool_max_idle_per_host(REQUESTS)
            .build()
            .unwrap();
        let url = format!("http://{target_host}:{target_port}/codec");
        let mut requests = JoinSet::new();
        for _ in 0..REQUESTS {
            let client = client.clone();
            let url = url.clone();
            requests.spawn(async move {
                let response = client.get(url).send().await.unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                assert_eq!(response.text().await.unwrap(), "ok");
            });
        }

        tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(result) = requests.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();

        proxy_task.abort();
        target_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reqwest_socks5_connect_is_concurrent_and_interoperable() {
        run_reqwest_interop("socks5", "127.0.0.1", AuthAdaptor::no(), None, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reqwest_socks5h_connect_is_concurrent_and_interoperable() {
        run_reqwest_interop("socks5h", "localhost", AuthAdaptor::no(), None, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reqwest_socks5_password_auth_is_concurrent_and_interoperable() {
        run_reqwest_interop(
            "socks5h",
            "localhost",
            AuthAdaptor::password("codec-user", "codec-password"),
            Some(("codec-user", "codec-password")),
            false,
        )
        .await;
    }

    #[cfg(feature = "management")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reqwest_managed_socks5_credentials_are_interoperable() {
        use crate::access::{
            Reader,
            tests::{ROUTED_LOGIN as LOGIN, routed_policy as policy, secret},
        };
        let reader = Reader::new(policy(1, 64)).unwrap();
        let secret = String::from_utf8(secret()).unwrap();
        run_reqwest_interop(
            "socks5h",
            "localhost",
            AuthAdaptor::Managed(reader),
            Some((LOGIN, &secret)),
            true,
        )
        .await;
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_socks5_holds_lease_during_bind_wait_and_udp_control_lifetime() {
        use crate::access::{
            Protocol, Reader,
            tests::{ROUTED_LOGIN as LOGIN, routed_policy as policy, secret},
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            for command in [0x02, 0x03] {
                let reader = Reader::new(policy(1, 1)).unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let auth = Arc::new(AuthAdaptor::Managed(reader.clone()));
                let server = tokio::spawn(async move {
                    let (stream, peer) = listener.accept().await.unwrap();
                    handle(
                        IncomingConnection::new(stream, auth),
                        peer,
                        Connector::new(
                            Some("192.0.2.1/32".parse().unwrap()),
                            None,
                            None,
                            3,
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            None,
                            None,
                        ),
                    )
                    .await
                });
                let mut client = TcpStream::connect(address).await.unwrap();
                client.write_all(&[5, 1, 2]).await.unwrap();
                let mut response = [0; 2];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, 2]);
                let password = secret();
                let mut credentials = vec![1, u8::try_from(LOGIN.len()).unwrap()];
                credentials.extend_from_slice(LOGIN.as_bytes());
                credentials.push(u8::try_from(password.len()).unwrap());
                credentials.extend_from_slice(&password);
                client.write_all(&credentials).await.unwrap();
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [1, 0]);
                write_socks5_request(
                    &mut client,
                    command,
                    &Address::from("0.0.0.0:0".parse::<SocketAddr>().unwrap()),
                )
                .await;
                let (reply, bound) = read_socks5_reply(&mut client).await;
                assert_eq!(reply, Reply::Succeeded);
                let Address::SocketAddress(bound) = bound else {
                    panic!("expected socket reply")
                };
                if command == 0x02 {
                    assert_eq!(bound.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
                } else {
                    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let target_addr = target.local_addr().unwrap();
                    let echo = tokio::spawn(async move {
                        let mut bytes = [0; 32];
                        let (size, peer) = target.recv_from(&mut bytes).await.unwrap();
                        assert_eq!(peer.ip(), "127.0.0.2".parse::<std::net::IpAddr>().unwrap());
                        target.send_to(&bytes[..size], peer).await.unwrap();
                    });
                    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    udp.send_to(
                        &udp_relay_packet(0, Address::from(target_addr), b"managed source"),
                        bound,
                    )
                    .await
                    .unwrap();
                    assert_udp_relay_response(
                        &udp,
                        bound,
                        Address::from(target_addr),
                        b"managed source",
                    )
                    .await;
                    echo.await.unwrap();
                }
                assert!(matches!(
                    reader.authenticate(LOGIN, &password, Protocol::Http),
                    Err(crate::access::Error::Capacity)
                ));
                reader.publish(policy(2, 1)).unwrap();
                assert!(matches!(
                    reader.authenticate(LOGIN, &password, Protocol::Socks5),
                    Err(crate::access::Error::Capacity)
                ));
                client.shutdown().await.unwrap();
                drop(client);
                let _ = server.await.unwrap();
                assert!(
                    reader
                        .authenticate(LOGIN, &password, Protocol::Socks5)
                        .is_ok()
                );
            }
        })
        .await
        .expect("managed SOCKS5 admission must end with its control connection");
    }

    #[cfg(feature = "management")]
    async fn metered_socks5_connection() -> (
        TcpStream,
        tokio::task::JoinHandle<std::io::Result<()>>,
        crate::access::Reader,
    ) {
        use crate::access::{
            Reader,
            tests::{ROUTED_LOGIN as LOGIN, routed_policy, secret},
        };

        let reader = Reader::new(routed_policy(1, 8)).unwrap();
        let auth = Arc::new(AuthAdaptor::Managed(reader.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await?;
            handle(
                IncomingConnection::new(stream, auth),
                peer,
                test_connector(),
            )
            .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);

        let password = secret();
        let mut credentials = vec![1, u8::try_from(LOGIN.len()).unwrap()];
        credentials.extend_from_slice(LOGIN.as_bytes());
        credentials.push(u8::try_from(password.len()).unwrap());
        credentials.extend_from_slice(&password);
        client.write_all(&credentials).await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
        (client, server, reader)
    }

    #[cfg(feature = "management")]
    fn socks5_traffic(reader: &crate::access::Reader) -> crate::traffic::Snapshot {
        let snapshots = reader.traffic_registry().snapshot().unwrap();
        let matching = snapshots
            .iter()
            .filter(|series| series.protocol == crate::access::Protocol::Socks5)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        matching[0].value
    }

    #[cfg(feature = "management")]
    fn assert_socks5_traffic(reader: &crate::access::Reader, upload: u64, download: u64) {
        assert_eq!(
            socks5_traffic(reader),
            crate::traffic::Snapshot {
                upload,
                download,
                saturated: false,
            }
        );
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_socks5_connect_counts_live_payload_once_and_retains_it_after_cancel() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (mut client, server, reader) = metered_socks5_connection().await;
            assert_socks5_traffic(&reader, 0, 0);

            let mut request = socks5_request(1, &Address::from(address));
            request.extend_from_slice(b"prefetched-");
            client.write_all(&request).await.unwrap();
            assert_eq!(read_socks5_reply(&mut client).await.0, Reply::Succeeded);
            let (mut target, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
            let mut pending = [0; 11];
            target.read_exact(&mut pending).await.unwrap();
            assert_eq!(&pending, b"prefetched-");

            let upload = vec![0x61; 32_769];
            client.write_all(&upload).await.unwrap();
            let mut received = vec![0; upload.len()];
            target.read_exact(&mut received).await.unwrap();
            assert_eq!(received, upload);
            let download = vec![0x62; 16_387];
            target.write_all(&download).await.unwrap();
            let mut received = vec![0; download.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, download);
            assert_socks5_traffic(&reader, 32_780, 16_387);

            // Publication and the last flow disappearing must not erase bytes
            // already accepted while the tunnel was still open.
            reader
                .publish(crate::access::tests::routed_policy(2, 8))
                .unwrap();
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            assert_socks5_traffic(&reader, 32_780, 16_387);
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_socks5_bind_counts_only_payload_after_second_reply() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (mut client, server, reader) = metered_socks5_connection().await;
            let target = TcpSocket::new_v4().unwrap();
            target.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = target.local_addr().unwrap();
            let mut request = socks5_request(2, &Address::from(address));
            request.extend_from_slice(b"prefetched-");
            client.write_all(&request).await.unwrap();
            let (reply, bound) = read_socks5_reply(&mut client).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(bound) = bound else {
                panic!("expected BIND socket address");
            };
            client.write_all(b"early-").await.unwrap();
            // Before a peer exists, buffering DATA and the first reply are not
            // successful forwarding. No timing/sleep assumption is needed.
            assert_socks5_traffic(&reader, 0, 0);
            let mut target = target.connect(bound).await.unwrap();
            assert_eq!(read_socks5_reply(&mut client).await.0, Reply::Succeeded);
            let mut early = [0; 17];
            target.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"prefetched-early-");

            client.write_all(b"late").await.unwrap();
            let mut late = [0; 4];
            target.read_exact(&mut late).await.unwrap();
            assert_eq!(&late, b"late");
            target.write_all(b"return payload").await.unwrap();
            let mut response = [0; 14];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"return payload");
            assert_socks5_traffic(&reader, 21, 14);
            client.shutdown().await.unwrap();
            target.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
            assert_socks5_traffic(&reader, 21, 14);
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_socks5_udp_counts_accepted_payload_not_headers_or_dropped_packets() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = remote.local_addr().unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let unauthorized = UdpSocket::bind("127.0.0.3:0").await.unwrap();
            let (mut client, server, reader) = metered_socks5_connection().await;
            write_udp_associate_request(&mut client, &Address::from(udp.local_addr().unwrap()))
                .await;
            let (reply, relay) = read_socks5_reply(&mut client).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(relay) = relay else {
                panic!("expected UDP relay socket address");
            };
            assert_socks5_traffic(&reader, 0, 0);

            let invalid = udp_relay_packet(0, Address::from(address), b"unauthorized");
            unauthorized.send_to(&invalid, relay).await.unwrap();
            udp.send_to(&[0, 0, 0, 1, 127], relay).await.unwrap();
            udp.send_to(
                &udp_relay_packet(1, Address::from(address), b"fragment"),
                relay,
            )
            .await
            .unwrap();
            udp.send_to(
                &udp_relay_packet(0, Address::from(address), b"upload payload"),
                relay,
            )
            .await
            .unwrap();
            let mut buffer = vec![0; MAX_UDP_DATAGRAM_SIZE];
            let (length, source) = remote.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"upload payload");
            assert_eq!(source.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
            remote.send_to(b"download payload", source).await.unwrap();
            assert_udp_relay_response(&udp, relay, Address::from(address), b"download payload")
                .await;
            assert_socks5_traffic(&reader, 14, 16);

            client.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
            assert_socks5_traffic(&reader, 14, 16);

            // Exercise a real send failure separately: two back-to-back UDP
            // packets near the receive-buffer limit could drop a sentinel and
            // make a relay-loop barrier timing dependent. A fresh readable
            // socket lets this call observe the oversized response directly.
            let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let inbound = AssociatedUdpSocket::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let authorized = reader
                .authenticate(
                    crate::access::tests::ROUTED_LOGIN,
                    &crate::access::tests::secret(),
                    crate::access::Protocol::Socks5,
                )
                .unwrap();
            let meter = authorized.lease.meter(Direction::Download);
            remote
                .send_to(&vec![0x5a; 65_507], outbound.local_addr().unwrap())
                .await
                .unwrap();
            outbound.readable().await.unwrap();
            let mut response_buffer = BytesMut::new();
            let error = forward_udp_response(
                &inbound,
                &outbound,
                &mut buffer,
                &mut response_buffer,
                udp.local_addr().unwrap().ip(),
                udp.local_addr().unwrap().port(),
                Some(&meter),
            )
            .await;
            assert!(error.is_err());
            assert_socks5_traffic(&reader, 14, 16);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1929_pipelined_auth_request_and_application_data_are_preserved() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let target = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let target_address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0; 9];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"pipelined");
                stream.write_all(&payload).await.unwrap();
            });

            let proxy = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let proxy_address = proxy.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, peer) = proxy.accept().await?;
                handle(
                    IncomingConnection::new(
                        stream,
                        Arc::new(AuthAdaptor::password("codec-user", "codec-password")),
                    ),
                    peer,
                    test_connector(),
                )
                .await
            });

            // TCP can coalesce RFC 1928 method negotiation, RFC 1929
            // authentication, the CONNECT request, and application data. Each
            // decoder state must consume only its own length-delimited frame.
            let mut request = Vec::new();
            request.extend_from_slice(&[0x05, 0x01, 0x02]);
            request.extend_from_slice(&[
                0x01, 0x0a, b'c', b'o', b'd', b'e', b'c', b'-', b'u', b's', b'e', b'r', 0x0e, b'c',
                b'o', b'd', b'e', b'c', b'-', b'p', b'a', b's', b's', b'w', b'o', b'r', b'd',
            ]);
            request.extend_from_slice(&socks5_request(0x01, &Address::from(target_address)));
            request.extend_from_slice(b"pipelined");

            let mut client = TcpStream::connect(proxy_address).await.unwrap();
            client.write_all(&request).await.unwrap();

            let mut response = [0; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0x05, 0x02]);
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0x01, 0x00]);
            let (reply, _) = read_socks5_reply(&mut client).await;
            assert_eq!(reply, Reply::Succeeded);

            let mut echoed = [0; 9];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"pipelined");
            client.shutdown().await.unwrap();

            target_task.await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1929_failure_status_is_followed_by_connection_close() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(
                IncomingConnection::new(
                    stream,
                    Arc::new(AuthAdaptor::password("expected", "secret")),
                )
                .authenticate()
                .await
                .is_err()
            );
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x02]);

        client
            .write_all(&[
                0x01, 0x05, b'w', b'r', b'o', b'n', b'g', 0x05, b'w', b'r', b'o', b'n', b'g',
            ])
            .await
            .unwrap();
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x01, 0xff]);
        assert_eq!(client.read(&mut response).await.unwrap(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rfc1928_udp_associate_relays_until_control_connection_closes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let echo_address = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                let mut payload = [0; 64];
                let (len, peer) = echo.recv_from(&mut payload).await.unwrap();
                assert_eq!(&payload[..len], b"udp round trip");
                echo.send_to(&payload[..len], peer).await.unwrap();
            });

            let client_udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let client_udp_address = client_udp.local_addr().unwrap();
            let (mut control, server) = start_socks5_connection().await;
            let proxy_ip = control.peer_addr().unwrap().ip();

            write_udp_associate_request(&mut control, &Address::from(client_udp_address)).await;
            let (reply, relay_address) = read_socks5_reply(&mut control).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(relay_address) = relay_address else {
                panic!("UDP ASSOCIATE reply did not contain a socket address");
            };
            assert_eq!(relay_address.ip(), proxy_ip);
            assert_ne!(relay_address.port(), 0);

            let request = udp_relay_packet(0, Address::from(echo_address), b"udp round trip");
            client_udp.send_to(&request, relay_address).await.unwrap();
            assert_udp_relay_response(
                &client_udp,
                relay_address,
                Address::from(echo_address),
                b"udp round trip",
            )
            .await;
            echo_task.await.unwrap();
            assert!(!server.is_finished());

            control.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_udp_associate_relays_datagrams_larger_than_ethernet_mtu() {
        tokio::time::timeout(
            Duration::from_secs(5),
            assert_udp_associate_round_trip(8192),
        )
        .await
        .unwrap();
    }

    // This wire-size boundary requires the host to accept a 65,507-octet UDP
    // payload. Linux and Windows CI expose that full IPv4 limit; the portable
    // test above still covers large datagrams on hosts with lower socket caps.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn rfc1928_udp_associate_relays_maximum_ipv4_datagram_without_truncation() {
        // IPv4's 16-bit total-length field leaves 65,507 octets after the
        // minimum 20-octet IP header and the 8-octet UDP header. RFC 1928
        // requires the client to subtract the SOCKS5 header from that
        // available space.
        // https://www.rfc-editor.org/rfc/rfc1928.html#section-7
        tokio::time::timeout(
            Duration::from_secs(5),
            assert_udp_associate_round_trip(65_507),
        )
        .await
        .unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn rfc1928_udp_associate_drops_response_that_cannot_fit_socks_header() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let remote = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let remote_address = remote.local_addr().unwrap();
            let client_udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let client_udp_address = client_udp.local_addr().unwrap();
            let (mut control, server) = start_socks5_connection().await;

            write_udp_associate_request(&mut control, &Address::from(client_udp_address)).await;
            let (reply, relay_address) = read_socks5_reply(&mut control).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(relay_address) = relay_address else {
                panic!("UDP ASSOCIATE reply did not contain a socket address");
            };

            let request = udp_relay_packet(0, Address::from(remote_address), b"prime");
            client_udp.send_to(&request, relay_address).await.unwrap();
            let mut packet = vec![0; MAX_UDP_DATAGRAM_SIZE];
            let (len, proxy_outbound) =
                tokio::time::timeout(Duration::from_secs(1), remote.recv_from(&mut packet))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&packet[..len], b"prime");

            remote
                .send_to(&vec![0x5a; 65_507], proxy_outbound)
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(250),
                    client_udp.recv_from(&mut packet)
                )
                .await
                .is_err()
            );
            assert!(!server.is_finished());

            remote
                .send_to(b"still alive", proxy_outbound)
                .await
                .unwrap();
            assert_udp_relay_response(
                &client_udp,
                relay_address,
                Address::from(remote_address),
                b"still alive",
            )
            .await;

            control.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_udp_associate_silently_drops_fragments_and_keeps_working() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let echo_address = echo.local_addr().unwrap();
            let client_udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let client_udp_address = client_udp.local_addr().unwrap();
            let (mut control, server) = start_socks5_connection().await;

            write_udp_associate_request(&mut control, &Address::from(client_udp_address)).await;
            let (reply, relay_address) = read_socks5_reply(&mut control).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(relay_address) = relay_address else {
                panic!("UDP ASSOCIATE reply did not contain a socket address");
            };

            let fragmented = udp_relay_packet(1, Address::from(echo_address), b"drop me");
            client_udp
                .send_to(&fragmented, relay_address)
                .await
                .unwrap();
            let mut payload = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(250), echo.recv_from(&mut payload))
                    .await
                    .is_err()
            );
            assert!(!server.is_finished());

            let request = udp_relay_packet(0, Address::from(echo_address), b"relay me");
            client_udp.send_to(&request, relay_address).await.unwrap();
            let (len, proxy) =
                tokio::time::timeout(Duration::from_secs(1), echo.recv_from(&mut payload))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&payload[..len], b"relay me");
            echo.send_to(&payload[..len], proxy).await.unwrap();
            assert_udp_relay_response(
                &client_udp,
                relay_address,
                Address::from(echo_address),
                b"relay me",
            )
            .await;

            control.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_udp_associate_drops_unauthorized_source_ip_without_closing() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let echo_address = echo.local_addr().unwrap();
            let client = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let (mut control, server) = start_socks5_connection().await;

            // RFC 5737 reserves 192.0.2.0/24 for documentation, so it cannot
            // accidentally match the loopback source used by this test.
            // https://www.rfc-editor.org/rfc/rfc5737.html#section-3
            let expected_source = SocketAddr::from((
                std::net::Ipv4Addr::new(192, 0, 2, 1),
                client.local_addr().unwrap().port(),
            ));
            write_udp_associate_request(&mut control, &Address::from(expected_source)).await;
            let (reply, relay_address) = read_socks5_reply(&mut control).await;
            assert_eq!(reply, Reply::Succeeded);
            let Address::SocketAddress(relay_address) = relay_address else {
                panic!("UDP ASSOCIATE reply did not contain a socket address");
            };

            let request = udp_relay_packet(0, Address::from(echo_address), b"unauthorized");
            client.send_to(&request, relay_address).await.unwrap();
            let mut payload = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(250), echo.recv_from(&mut payload))
                    .await
                    .is_err()
            );
            assert!(!server.is_finished());

            control.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_connect_forwards_data_prefetched_by_request_codec_once() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let target = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let target_address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut target, _) = target.accept().await.unwrap();
                let mut payload = [0; 16];
                target.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"client to target");
                target.write_all(b"target to client").await.unwrap();
                target.shutdown().await.unwrap();
            });
            let (mut client, server) = start_socks5_connection().await;
            let mut request = socks5_request(0x01, &Address::from(target_address));
            request.extend_from_slice(b"client to target");

            client.write_all(&request).await.unwrap();
            let (reply, _) = read_socks5_reply(&mut client).await;
            assert_eq!(reply, Reply::Succeeded);
            let mut response = [0; 16];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"target to client");

            client.shutdown().await.unwrap();
            target_task.await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_bind_sends_two_success_replies_and_relays_data() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, server) = start_socks5_connection().await;
            let target_socket = TcpSocket::new_v4().unwrap();
            target_socket
                .bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
            let target_address = target_socket.local_addr().unwrap();

            let mut request = socks5_request(0x02, &Address::from(target_address));
            request.extend_from_slice(b"prefetched-");
            client.write_all(&request).await.unwrap();
            let (first_reply, bind_address) = read_socks5_reply(&mut client).await;
            assert_eq!(first_reply, Reply::Succeeded);
            let Address::SocketAddress(bind_address) = bind_address else {
                panic!("BIND reply did not contain a socket address");
            };

            client.write_all(b"early").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut target = target_socket.connect(bind_address).await.unwrap();
            let (second_reply, peer_address) = read_socks5_reply(&mut client).await;
            assert_eq!(second_reply, Reply::Succeeded);
            assert_eq!(peer_address, Address::from(target_address));

            let mut from_client = [0; 16];
            target.read_exact(&mut from_client).await.unwrap();
            assert_eq!(&from_client, b"prefetched-early");

            target.write_all(b"target to client").await.unwrap();
            let mut from_target = [0; 16];
            client.read_exact(&mut from_target).await.unwrap();
            assert_eq!(&from_target, b"target to client");

            client.shutdown().await.unwrap();
            target.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_bind_releases_listener_when_control_connection_closes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, server) = start_socks5_connection().await;
            write_bind_request(&mut client, &Address::unspecified()).await;
            let (first_reply, _) = read_socks5_reply(&mut client).await;
            assert_eq!(first_reply, Reply::Succeeded);

            client.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_bind_limits_data_buffered_before_second_reply() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, server) = start_socks5_connection().await;
            write_bind_request(&mut client, &Address::unspecified()).await;
            let (first_reply, _) = read_socks5_reply(&mut client).await;
            assert_eq!(first_reply, Reply::Succeeded);

            client
                .write_all(&vec![0x5a; MAX_BIND_EARLY_DATA + 1])
                .await
                .unwrap();
            let (second_reply, _) = read_socks5_reply(&mut client).await;
            assert_eq!(second_reply, Reply::GeneralFailure);

            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            assert_eq!(
                server.await.unwrap().unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_bind_rejection_sends_second_failure_reply_then_closes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, server) = start_socks5_connection().await;
            let target_socket = TcpSocket::new_v4().unwrap();
            target_socket
                .bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
            let target_address = target_socket.local_addr().unwrap();
            let unexpected_address =
                SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 2), target_address.port()));

            write_bind_request(&mut client, &Address::from(unexpected_address)).await;
            let (first_reply, bind_address) = read_socks5_reply(&mut client).await;
            assert_eq!(first_reply, Reply::Succeeded);
            let Address::SocketAddress(bind_address) = bind_address else {
                panic!("BIND reply did not contain a socket address");
            };

            let mut target = target_socket.connect(bind_address).await.unwrap();
            let (second_reply, peer_address) = read_socks5_reply(&mut client).await;
            assert_eq!(second_reply, Reply::ConnectionNotAllowed);
            assert_eq!(peer_address, Address::from(target_address));

            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            assert_eq!(target.read(&mut byte).await.unwrap(), 0);
            assert_eq!(
                server.await.unwrap().unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rfc1928_bind_resolution_error_sends_second_failure_reply_then_closes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut client, server) = start_socks5_connection().await;
            let target_socket = TcpSocket::new_v4().unwrap();
            target_socket
                .bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
            let target_address = target_socket.local_addr().unwrap();

            write_bind_request(
                &mut client,
                &Address::DomainAddress("\0".to_owned(), target_address.port()),
            )
            .await;
            let (first_reply, bind_address) = read_socks5_reply(&mut client).await;
            assert_eq!(first_reply, Reply::Succeeded);
            let Address::SocketAddress(bind_address) = bind_address else {
                panic!("BIND reply did not contain a socket address");
            };

            let mut target = target_socket.connect(bind_address).await.unwrap();
            let (second_reply, peer_address) = read_socks5_reply(&mut client).await;
            assert_eq!(second_reply, Reply::HostUnreachable);
            assert_eq!(peer_address, Address::from(target_address));

            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            assert_eq!(target.read(&mut byte).await.unwrap(), 0);
            assert!(server.await.unwrap().is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn bind_peer_validation_honors_address_and_wildcards() {
        let actual = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 4242));
        assert!(
            bind_peer_matches(
                &Address::from((std::net::Ipv4Addr::LOCALHOST, 4242)),
                actual
            )
            .await
            .unwrap()
        );
        assert!(
            bind_peer_matches(&Address::unspecified(), actual)
                .await
                .unwrap()
        );
        assert!(
            !bind_peer_matches(
                &Address::from((std::net::Ipv4Addr::LOCALHOST, 4243)),
                actual
            )
            .await
            .unwrap()
        );

        let mapped_actual = SocketAddr::from((
            "::ffff:127.0.0.1".parse::<std::net::Ipv6Addr>().unwrap(),
            actual.port(),
        ));
        assert!(
            bind_peer_matches(&Address::from(actual), mapped_actual)
                .await
                .unwrap()
        );
        assert!(
            bind_peer_matches(
                &Address::DomainAddress("127.0.0.1".to_owned(), actual.port()),
                mapped_actual,
            )
            .await
            .unwrap()
        );
    }
}

#[cfg(test)]
mod preset_tests {
    //! Command-stage tests: SOCKS authentication precedes knowing TCP vs UDP/BIND.

    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    async fn command(
        auth: AuthAdaptor,
        username: &str,
        password: &[u8],
        command: u8,
        expected: u8,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.unwrap();
                handle(
                    IncomingConnection::new(stream, Arc::new(auth)),
                    peer,
                    Connector::new(
                        None,
                        None,
                        None,
                        1,
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        None,
                        None,
                    ),
                )
                .await
                .unwrap();
            });
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&[5, 1, 2]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 2]);
            let mut authentication = vec![1, u8::try_from(username.len()).unwrap()];
            authentication.extend_from_slice(username.as_bytes());
            authentication.push(u8::try_from(password.len()).unwrap());
            authentication.extend_from_slice(password);
            stream.write_all(&authentication).await.unwrap();
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(
                method,
                [1, 0],
                "authentication does not know the command yet"
            );
            stream
                .write_all(&[5, command, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, expected, 0, 1]);
            if expected != 0 {
                assert_eq!(stream.read(&mut method).await.unwrap(), 0);
            }
            drop(stream);
            server.await.unwrap();
        })
        .await
        .expect("preset command must finish and release its admission");
    }

    #[tokio::test]
    async fn explicit_tcp_device_on_udp_or_passive_bind_is_a_ruleset_denial() {
        for operation in [2, 3] {
            command(
                AuthAdaptor::password("user", "password"),
                "user-device-linux",
                b"password",
                operation,
                2,
            )
            .await;
        }
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_tcp_default_does_not_change_udp_or_bind_but_requires_backend_for_connect() {
        use crate::access::{
            Reader,
            tests::{LOGIN, policy, secret},
        };
        for (operation, expected) in [(1, 1), (2, 0), (3, 0)] {
            let mut data = policy(1, 1);
            data.presets.users[0].default_preset = Some(crate::ebpf::Profile::Linux);
            data.presets.users[0].allowed_presets = vec![crate::ebpf::Profile::Linux];
            let reader = Reader::new(data).unwrap();
            command(
                AuthAdaptor::Managed(reader.clone()),
                LOGIN,
                &secret(),
                operation,
                expected,
            )
            .await;
            assert!(
                reader
                    .authenticate(LOGIN, &secret(), crate::access::Protocol::Socks5)
                    .is_ok(),
                "command teardown must release its lease"
            );
        }
    }
}
