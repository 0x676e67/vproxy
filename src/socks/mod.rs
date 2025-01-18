pub mod error;
pub mod proto;
pub mod server;

use self::{
    proto::{Address, Reply, UdpHeader},
    server::{
        connection::associate::{self, AssociatedUdpSocket},
        ClientConnection, IncomingConnection, Server, UdpAssociate,
    },
};
use crate::{connect::Connector, extension::Extension, serve::Context};
use error::Error;
use server::{
    connection::connect::{self, Connect},
    AuthAdaptor,
};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{instrument, Level};

pub async fn proxy(ctx: Context) -> crate::Result<()> {
    tracing::info!("Socks5 server listening on {}", ctx.bind);

    match (&ctx.auth.username, &ctx.auth.password) {
        (Some(username), Some(password)) => {
            let auth = AuthAdaptor::new_password(username, password);
            let server =
                Server::bind_with_concurrency(ctx.bind, ctx.concurrent as u32, auth).await?;

            event_loop(server, ctx.connector).await?;
        }

        _ => {
            let server = Server::bind_with_concurrency(
                ctx.bind,
                ctx.concurrent as u32,
                AuthAdaptor::new_no_auth(),
            )
            .await?;
            event_loop(server, ctx.connector).await?;
        }
    }

    Ok(())
}

async fn event_loop(server: Server, connector: Connector) -> std::io::Result<()> {
    let connector = Arc::new(connector);
    while let Ok((conn, _)) = server.accept().await {
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(conn, connector).await {
                tracing::info!("{err}");
            }
        });
    }
    Ok(())
}

async fn handle(conn: IncomingConnection, connector: Arc<Connector>) -> std::io::Result<()> {
    let (conn, res) = conn.authenticate().await?;
    let (res, extension) = res?;

    if !res {
        tracing::info!("authentication failed");
        return Ok(());
    }

    match conn.wait_request().await? {
        ClientConnection::Connect(connect, addr) => {
            hanlde_tcp_proxy(connector, connect, addr, extension).await
        }
        ClientConnection::UdpAssociate(associate, addr) => {
            handle_udp_proxy(connector, associate, addr, extension).await
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await
        }
    }
}

#[instrument(skip(connector, connect), level = Level::DEBUG)]
async fn hanlde_tcp_proxy(
    connector: Arc<Connector>,
    connect: Connect<connect::NeedReply>,
    addr: Address,
    extension: Extension,
) -> std::io::Result<()> {
    let target_stream = match addr {
        Address::DomainAddress(domain, port) => {
            connector
                .tcp_connector()
                .connect_with_domain((domain, port), extension)
                .await
        }
        Address::SocketAddress(addr) => connector.tcp_connector().connect(addr, &extension).await,
    };

    match target_stream {
        Ok(mut target_stream) => {
            let mut conn = connect
                .reply(Reply::Succeeded, Address::unspecified())
                .await?;

            match tokio::io::copy_bidirectional(&mut target_stream, &mut conn).await {
                Ok((from_client, from_server)) => {
                    tracing::trace!(
                        "[TCP] client wrote {} bytes and received {} bytes",
                        from_client,
                        from_server
                    );
                }
                Err(err) => {
                    tracing::trace!("[TCP] tunnel error: {}", err);
                }
            };
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
async fn handle_udp_proxy(
    connector: Arc<Connector>,
    associate: UdpAssociate<associate::NeedReply>,
    addr: Address,
    extension: Extension,
) -> std::io::Result<()> {
    const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

    // listen on a random port
    let listen_ip = associate.local_addr()?.ip();
    let udp_socket = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    match udp_socket.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Ok((udp_socket, listen_addr)) => {
            tracing::info!("[UDP] {listen_addr} listen on");

            let mut reply_listener = associate
                .reply(Reply::Succeeded, Address::from(listen_addr))
                .await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((udp_socket, buf_size)));

            let incoming_addr = Arc::new(RwLock::new(SocketAddr::from(([0, 0, 0, 0], 0))));
            let dispatch_socket = connector.udp_connector().bind_socket(extension).await?;

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

                        tracing::trace!("[UDP] {src_addr} -> {dst_addr} incoming packet size {}", pkt.len());
                        let dst_addr = dst_addr.to_socket_addrs()?.next().ok_or("Invalid address")?;
                        dispatch_socket.send_to(&pkt, dst_addr).await?;
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
                        tracing::trace!("[UDP] {incoming_addr} <- {remote_addr} feedback to incoming");

                        listen_udp.send_to(&buf[..len], 0, remote_addr.into(), incoming_addr).await?;
                        Ok::<_, Error>(())
                    } => {
                        if res.is_err() {
                            break res;
                        }
                    },
                    _ = reply_listener.wait_until_closed() => {
                        tracing::trace!("[UDP] {} listener closed", listen_addr);
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
