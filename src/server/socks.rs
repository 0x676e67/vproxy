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

use bytes::BytesMut;
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
    proto::{Address, Reply},
};
use super::{
    Acceptor, Context, Handle, MAX_UDP_RELAY_PAYLOAD_SIZE, Server, drain_connections, io,
    is_oversized_datagram_error, log_connection_result,
};
use crate::connect::{Connector, TcpConnector, UdpConnector};

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
    async fn start(mut self, handle: Handle) -> std::io::Result<()> {
        tracing::info!(
            "Socks5 proxy server listening on {}",
            self.listener.local_addr()?
        );
        let mut connections = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break,
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = result {
                        log_connection_result(result, "SOCKS5");
                    }
                }
                conn = Socks5Server::incoming(&mut self.listener) => {
                    connections.spawn_on(
                        self.acceptor.clone().accept(conn, handle.clone()),
                        &pingora_runtime::current_handle(),
                    );
                }
            }
        }
        drain_connections(&mut connections, "SOCKS5").await;
        Ok(())
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
        Address::SocketAddress(addr) => {
            tracing::info!(
                "[SOCKS5][CONNECT] {} -> {} forwarding connection",
                connect.peer_addr()?,
                addr
            );
            connector.connect(addr).await
        }
        Address::DomainAddress(domain, port) => {
            tracing::info!(
                "[SOCKS5][CONNECT] {} -> {}:{} forwarding connection",
                connect.peer_addr()?,
                domain,
                port
            );
            connector.connect((domain, port)).await
        }
    };

    match outbound {
        Ok(mut outbound) => {
            let mut inbound = connect
                .reply(Reply::Succeeded, Address::unspecified())
                .await?;

            match io::copy_bidirectional(&mut inbound, &mut outbound).await {
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

// Keep the default bounded while allowing common 1,200-1,350 byte QUIC packets.
// AssociatedUdpSocket adds the largest RFC 1928 header and one truncation
// detection byte to its reusable receive buffer.
// https://www.rfc-editor.org/rfc/rfc1928.html#section-7
const UDP_PAYLOAD_RECV_BUFFER_SIZE: usize = MAX_UDP_RELAY_PAYLOAD_SIZE + 1;

#[instrument(skip(associate, connector), level = Level::DEBUG)]
async fn handle_udp(
    associate: UdpAssociate<associate::NeedReply>,
    address: Address,
    connector: UdpConnector<'_>,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((associate.local_addr()?.ip(), 0))).await?;
    let listen_addr = socket.local_addr()?;
    tracing::info!("[SOCKS5][UDP] listening on: {listen_addr}");

    let mut reply_listener = associate
        .reply(Reply::Succeeded, Address::from(listen_addr))
        .await?;

    let inbound = AssociatedUdpSocket::new(socket, MAX_UDP_RELAY_PAYLOAD_SIZE)?;
    let mut inbound_buffer = vec![0; inbound.recv_buffer_size()];
    let mut preferred_buffer = [0; UDP_PAYLOAD_RECV_BUFFER_SIZE];
    let mut fallback_buffer = [0; UDP_PAYLOAD_RECV_BUFFER_SIZE];
    let mut preferred_response = BytesMut::new();
    let mut fallback_response = BytesMut::new();
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
                let (pkt, frag, dst_addr, src_addr) = inbound.recv_from(&mut inbound_buffer).await?;

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

                match dst_addr {
                    Address::SocketAddress(target_addr) => {
                        tracing::info!("[SOCKS5][UDP] {src_addr} -> {target_addr} forwarding packet, size {}", pkt.len());
                        connector
                            .send_packet(pkt, target_addr, &preferred_outbound, fallback_outbound.as_ref())
                            .await?;
                    }
                    Address::DomainAddress(domain, port) => {
                        tracing::info!("[SOCKS5][UDP] {src_addr} -> {domain}:{port} forwarding packet, size {}", pkt.len());
                        connector
                            .send_packet(pkt, (domain, port), &preferred_outbound, fallback_outbound.as_ref())
                            .await?;
                    }
                }

                Ok(())
            } => req,

            preferred_resp = async {
                let (len, remote_addr) = match preferred_outbound.recv_from(&mut preferred_buffer).await {
                    Ok(received) => received,
                    Err(error) if is_oversized_datagram_error(&error) => return Ok(()),
                    Err(error) => return Err(Error::from(error)),
                };
                if len > MAX_UDP_RELAY_PAYLOAD_SIZE {
                    tracing::trace!("[SOCKS5][UDP] dropping oversized packet from {remote_addr}");
                    return Ok(());
                }
                let src_addr = SocketAddr::new(src_ip, src_port.load(Ordering::Relaxed));

                tracing::info!("[SOCKS5][UDP] {src_addr} <- {remote_addr} feedback to incoming, packet size {len}");

                inbound
                    .send_to_buffered(
                        &preferred_buffer[..len],
                        0,
                        remote_addr.into(),
                        src_addr,
                        &mut preferred_response,
                    )
                    .await
                    .map(|_| ())
                    .map_err(Error::from)
            } => preferred_resp,

            fallback_resp = async {
                if let Some(ref fallback_outbound) = fallback_outbound {
                    let (len, remote_addr) = match fallback_outbound.recv_from(&mut fallback_buffer).await {
                        Ok(received) => received,
                        Err(error) if is_oversized_datagram_error(&error) => return Ok(()),
                        Err(error) => return Err(Error::from(error)),
                    };
                    if len > MAX_UDP_RELAY_PAYLOAD_SIZE {
                        tracing::trace!("[SOCKS5][UDP] dropping oversized packet from {remote_addr}");
                        return Ok(());
                    }
                    let src_addr = SocketAddr::new(src_ip, src_port.load(Ordering::Relaxed));

                    tracing::info!("[SOCKS5][UDP] {src_addr} <- {remote_addr} feedback to incoming, packet size {len}");

                    inbound
                        .send_to_buffered(
                            &fallback_buffer[..len],
                            0,
                            remote_addr.into(),
                            src_addr,
                            &mut fallback_response,
                        )
                        .await
                        .map(|_| ())
                        .map_err(Error::from)
                } else {
                    // If there's no secondary socket, just await forever.
                    tokio::task::yield_now().await;
                    futures_util::future::pending().await
                }
            } => fallback_resp,

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
            match io::copy_bidirectional(&mut inbound, &mut outbound).await {
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use tokio::{net::UdpSocket, time::timeout};

    use super::{Address, AssociatedUdpSocket, MAX_UDP_RELAY_PAYLOAD_SIZE};

    #[tokio::test]
    async fn udp_relay_buffer_accepts_a_quic_sized_datagram() {
        const QUIC_PACKET_SIZE: usize = 1350;

        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_address = receiver_socket.local_addr().unwrap();
        let receiver =
            AssociatedUdpSocket::new(receiver_socket, MAX_UDP_RELAY_PAYLOAD_SIZE).unwrap();
        let mut receive_buffer = vec![0; receiver.recv_buffer_size()];

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = AssociatedUdpSocket::new(sender_socket, MAX_UDP_RELAY_PAYLOAD_SIZE).unwrap();
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 443)));
        let payload = vec![0x5a; QUIC_PACKET_SIZE];

        let sent = sender
            .send_to(&payload, 0, destination.clone(), receiver_address)
            .await
            .unwrap();
        assert_eq!(sent, payload.len());

        let (received, fragment, received_destination, _) = timeout(
            Duration::from_secs(1),
            receiver.recv_from(&mut receive_buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fragment, 0);
        assert_eq!(received_destination, destination);
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn udp_relay_drops_an_oversized_datagram_without_forwarding_a_truncated_packet() {
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_address = receiver_socket.local_addr().unwrap();
        let receiver =
            AssociatedUdpSocket::new(receiver_socket, MAX_UDP_RELAY_PAYLOAD_SIZE).unwrap();
        let mut receive_buffer = vec![0; receiver.recv_buffer_size()];

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = AssociatedUdpSocket::new(sender_socket, receiver.recv_buffer_size()).unwrap();
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 443)));
        let oversized = vec![0x5a; receiver.recv_buffer_size()];
        sender
            .send_to(&oversized, 0, destination.clone(), receiver_address)
            .await
            .unwrap();
        sender
            .send_to(b"valid", 0, destination.clone(), receiver_address)
            .await
            .unwrap();

        let (received, fragment, received_destination, _) = timeout(
            Duration::from_secs(1),
            receiver.recv_from(&mut receive_buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fragment, 0);
        assert_eq!(received_destination, destination);
        assert_eq!(received, b"valid");
    }
}
