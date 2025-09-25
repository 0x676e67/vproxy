mod auth;
mod conn;
mod error;
mod proto;

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::RwLock,
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
    extension::Extension,
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
        ClientConnection::Connect(connect, addr) => {
            hanlde_connect_proxy(connector.tcp_connector(), connect, addr, extension).await
        }
        ClientConnection::UdpAssociate(associate, addr) => {
            handle_udp_proxy(connector.udp_connector(), associate, addr, extension).await
        }
        ClientConnection::Bind(bind, addr) => {
            hanlde_bind_proxy(connector.tcp_connector(), bind, addr, extension).await
        }
    }
}

#[instrument(skip(connector, connect), level = Level::DEBUG)]
async fn hanlde_connect_proxy(
    connector: TcpConnector<'_>,
    connect: Connect<connect::NeedReply>,
    addr: Address,
    extension: Extension,
) -> std::io::Result<()> {
    let target_stream = match addr {
        Address::DomainAddress(domain, port) => {
            connector
                .connect_with_domain((domain, port), extension)
                .await
        }
        Address::SocketAddress(socket_addr) => connector.connect(socket_addr, extension).await,
    };

    match target_stream {
        Ok(mut target_stream) => {
            let mut conn = connect
                .reply(Reply::Succeeded, Address::unspecified())
                .await?;

            match tokio::io::copy_bidirectional(&mut target_stream, &mut conn).await {
                Ok((from_client, from_server)) => {
                    tracing::info!(
                        "[TCP] client wrote {} bytes and received {} bytes",
                        from_client,
                        from_server
                    );
                }
                Err(err) => {
                    tracing::trace!("[TCP] tunnel error: {}", err);
                }
            };

            target_stream.shutdown().await
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

#[instrument(skip(connector, associate), level = Level::DEBUG)]
async fn handle_udp_proxy(
    connector: UdpConnector<'_>,
    associate: UdpAssociate<associate::NeedReply>,
    _: Address,
    extension: Extension,
) -> std::io::Result<()> {
    const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

    let listen_ip = associate.local_addr()?.ip();
    let udp_socket = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await?;
    let listen_addr = udp_socket.local_addr()?;

    tracing::info!("[UDP] listen on: {listen_addr}");

    let mut reply_listener = associate
        .reply(Reply::Succeeded, Address::from(listen_addr))
        .await?;

    let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
    let listen_udp = AssociatedUdpSocket::from((udp_socket, buf_size));
    let dispatch_socket = connector.bind_socket(extension).await?;
    let incoming_addr = Arc::new(RwLock::new(SocketAddr::from(([0, 0, 0, 0], 0))));

    let result = tokio::select! {
        res = handle_client_to_remote(&listen_udp, &dispatch_socket, &connector, &incoming_addr, buf_size) => res,
        res = handle_remote_to_client(&dispatch_socket, &listen_udp, &incoming_addr) => res,
        _ = reply_listener.wait_until_closed() => {
            tracing::info!("[UDP] {} listener closed", listen_addr);
            Ok(())
        }
    };

    reply_listener.shutdown().await?;
    result.map_err(Into::into)
}

#[instrument(skip(connector), level = Level::DEBUG)]
async fn handle_client_to_remote(
    listen_udp: &AssociatedUdpSocket,
    dispatch_socket: &UdpSocket,
    connector: &UdpConnector<'_>,
    incoming_addr: &Arc<RwLock<SocketAddr>>,
    buf_size: usize,
) -> Result<(), Error> {
    loop {
        listen_udp.set_max_packet_size(buf_size);
        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;

        if frag != 0 {
            return Err("[UDP] packet fragment is not supported".into());
        }

        *incoming_addr.write().await = src_addr;
        tracing::info!(
            "[UDP] {src_addr} -> {dst_addr} incoming packet size {}",
            pkt.len()
        );

        match dst_addr {
            Address::SocketAddress(dst_addr) => {
                connector
                    .send_packet_with_addr(dispatch_socket, &pkt, dst_addr)
                    .await?;
            }
            Address::DomainAddress(domain, port) => {
                connector
                    .send_packet_with_domain(dispatch_socket, &pkt, (domain, port))
                    .await?;
            }
        }
    }
}

#[instrument(level = Level::DEBUG)]
async fn handle_remote_to_client(
    dispatch_socket: &UdpSocket,
    listen_udp: &AssociatedUdpSocket,
    incoming_addr: &Arc<RwLock<SocketAddr>>,
) -> Result<(), Error> {
    const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

    loop {
        let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
        let (len, remote_addr) = dispatch_socket.recv_from(&mut buf).await?;
        let incoming_addr = *incoming_addr.read().await;

        tracing::info!("[UDP] {incoming_addr} <- {remote_addr} feedback to incoming");
        listen_udp
            .send_to(&buf[..len], 0, remote_addr.into(), incoming_addr)
            .await?;
    }
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
///
/// # Arguments
///
/// * `connector` - The connector instance.
/// * `bind` - The BIND request details.
/// * `addr` - The address to bind to.
/// * `extension` - Additional extensions.
///
/// # Returns
///
/// A `Result` indicating success or failure.
#[instrument(skip(connector, bind, _addr), level = Level::DEBUG)]
async fn hanlde_bind_proxy(
    connector: TcpConnector<'_>,
    bind: Bind<bind::NeedFirstReply>,
    _addr: Address,
    extension: Extension,
) -> std::io::Result<()> {
    let listen_ip =
        connector.bind_socket_addr(|| bind.local_addr().map(|socket| socket.ip()), extension)?;
    let listener = TcpListener::bind(listen_ip).await?;

    let conn = bind
        .reply(Reply::Succeeded, Address::from(listener.local_addr()?))
        .await?;

    let (mut inbound, inbound_addr) = listener.accept().await?;
    tracing::info!("[BIND] accepted connection from {}", inbound_addr);

    match conn
        .reply(Reply::Succeeded, Address::from(inbound_addr))
        .await
    {
        Ok(mut conn) => {
            match tokio::io::copy_bidirectional(&mut inbound, &mut conn).await {
                Ok((a, b)) => {
                    tracing::trace!("[BIND] client wrote {} bytes and received {} bytes", a, b);
                }
                Err(err) => {
                    tracing::trace!("[BIND] tunnel error: {}", err);
                }
            }

            drop(inbound);

            conn.shutdown().await
        }
        Err((err, tcp)) => {
            drop(tcp);
            return Err(err);
        }
    }
}
