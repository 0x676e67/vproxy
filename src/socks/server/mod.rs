use connection::{
    bind::{self, Bind},
    connect::{self, Connect},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

pub mod auth;
pub mod connection;

use super::{
    proto::{Address, Reply, UdpHeader},
    server::connection::associate::{self, AssociatedUdpSocket},
};
pub use crate::socks::server::{
    auth::AuthAdaptor,
    connection::{associate::UdpAssociate, ClientConnection, IncomingConnection},
};
use crate::{
    connect::Connector,
    serve::{Context, Serve},
    socks::error::Error,
};
use crate::{
    connect::{TcpConnector, UdpConnector},
    extension::Extension,
};

use tokio::{io::AsyncWriteExt, net::UdpSocket, sync::RwLock};
use tracing::{instrument, Level};

pub struct Socks5Server {
    listener: TcpListener,
    auth: Arc<AuthAdaptor>,
    connector: Connector,
}

impl Socks5Server {
    /// Create a new socks5 server
    pub fn new(ctx: Context) -> std::io::Result<Self> {
        let auth = match (ctx.auth.username, ctx.auth.password) {
            (Some(username), Some(password)) => AuthAdaptor::new_password(username, password),

            _ => AuthAdaptor::new_no_auth(),
        };

        let socket = if ctx.bind.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(ctx.bind)?;

        Ok(Self {
            listener: socket.listen(ctx.concurrent as _)?,
            auth: Arc::new(auth),
            connector: ctx.connector,
        })
    }
}

impl Serve for Socks5Server {
    async fn serve(self) -> std::io::Result<()> {
        tracing::info!("Socks5 server listening on {}", self.listener.local_addr()?);

        while let Ok((stream, socket_addr)) = self.listener.accept().await {
            let connector = self.connector.clone();
            let auth = self.auth.clone();
            tokio::spawn(async move {
                if let Err(err) = handle(
                    IncomingConnection::new(stream, auth),
                    socket_addr,
                    connector,
                )
                .await
                {
                    tracing::trace!("[SOCKS5] error: {}", err);
                }
            });
        }

        Ok(())
    }
}

async fn handle(
    conn: IncomingConnection,
    socket_addr: SocketAddr,
    connector: Connector,
) -> std::io::Result<()> {
    let (conn, res) = conn.authenticate().await?;
    let (res, extension) = res?;

    if !res {
        tracing::info!("[SOCKS5] authentication failed: {}", socket_addr);
        return Ok(());
    }

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
#[inline]
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
        Address::SocketAddress(socket_addr) => connector.connect(socket_addr, &extension).await,
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

            drop(target_stream);

            Ok(())
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
#[inline]
async fn handle_udp_proxy(
    connector: UdpConnector<'_>,
    associate: UdpAssociate<associate::NeedReply>,
    _: Address,
    extension: Extension,
) -> std::io::Result<()> {
    const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

    let listen_ip = associate.local_addr()?.ip();
    let udp_socket = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    match udp_socket.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((udp_socket, listen_addr)) => {
            tracing::info!("[UDP] listen on: {listen_addr}");

            let mut reply_listener = associate
                .reply(Reply::Succeeded, Address::from(listen_addr))
                .await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = AssociatedUdpSocket::from((udp_socket, buf_size));

            let incoming_addr = Arc::new(RwLock::new(SocketAddr::from(([0, 0, 0, 0], 0))));
            let dispatch_socket = connector.bind_socket(extension).await?;

            let res = loop {
                tokio::select! {
                    res = async {
                        let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
                        listen_udp.set_max_packet_size(buf_size);

                        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
                        if frag != 0 {
                            return Err("[UDP] packet fragment is not supported".into());
                        }
                        *incoming_addr.write().await = src_addr;
                        tracing::info!("[UDP] {src_addr} -> {dst_addr} incoming packet size {}", pkt.len());

                        match dst_addr {
                            Address::SocketAddress(dst_addr) => {
                                connector.send_packet_with_addr(&dispatch_socket, &pkt, dst_addr).await?;
                            }
                            Address::DomainAddress(domain, port) => {
                                connector.send_packet_with_domain(&dispatch_socket, &pkt, (domain, port)).await?;
                            }
                        };

                        Ok::<_, Error>(())
                    } => {
                        if res.is_err() {
                            break res;
                        }
                    },
                    res = async {
                        let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
                        let (len, remote_addr) = dispatch_socket.recv_from(&mut buf).await?;
                        let incoming_addr = *incoming_addr.read().await;
                        tracing::info!("[UDP] {incoming_addr} <- {remote_addr} feedback to incoming");

                        listen_udp.send_to(&buf[..len], 0, remote_addr.into(), incoming_addr).await?;
                        Ok::<_, Error>(())
                    } => {
                        if res.is_err() {
                            break res;
                        }
                    },
                    _ = reply_listener.wait_until_closed() => {
                        tracing::info!("[UDP] {} listener closed", listen_addr);
                        break Ok::<_, Error>(());
                    },
                };
            };

            reply_listener.shutdown().await?;

            res.map_err(Into::into)
        }
        Err(err) => {
            let mut conn = associate
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await?;
            conn.shutdown().await?;
            Err(err)
        }
    }
}

/// Handles the SOCKS5 BIND command, which is used to listen for inbound connections.
/// This is typically used in server mode applications, such as FTP passive mode.
///
/// ### Workflow
///
/// 1. **Client sends BIND request**
///    - Client sends a BIND request to the SOCKS5 proxy server.
///    - Proxy server responds with an IP address and port, which is the temporary listening port allocated by the proxy server.
///
/// 2. **Proxy server listens for inbound connections**
///    - Proxy server listens on the allocated temporary port.
///    - Proxy server sends a BIND response to the client, notifying the listening address and port.
///
/// 3. **Client receives BIND response**
///    - Client receives the BIND response from the proxy server, knowing the address and port the proxy server is listening on.
///
/// 4. **Target server initiates connection**
///    - Target server initiates a connection to the proxy server's listening address and port.
///
/// 5. **Proxy server accepts inbound connection**
///    - Proxy server accepts the inbound connection from the target server.
///    - Proxy server sends a second BIND response to the client, notifying that the inbound connection has been established.
///
/// 6. **Client receives second BIND response**
///    - Client receives the second BIND response from the proxy server, knowing that the inbound connection has been established.
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
#[inline]
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
