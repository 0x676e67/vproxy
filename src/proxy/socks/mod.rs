pub mod error;
pub mod proto;
pub mod server;

use self::{
    proto::{Address, Reply, UdpHeader},
    server::{
        auth,
        connection::associate::{self, AssociatedUdpSocket},
        ClientConnection, IncomingConnection, Server, UdpAssociate,
    },
};
use super::{extension::Extension, Context};
use crate::proxy::connect::Connector;
use error::Error;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{net::UdpSocket, sync::Mutex};

pub async fn proxy(ctx: Context) -> crate::Result<()> {
    tracing::info!("Socks5 server listening on {}", ctx.bind);

    match (&ctx.auth.username, &ctx.auth.password) {
        (Some(username), Some(password)) => {
            let auth = Arc::new(auth::Password::new(username, password)) as Arc<_>;
            let server =
                Server::bind_with_concurrency(ctx.bind, ctx.concurrent as u32, auth).await?;

            event_loop(server, ctx.connector).await?;
        }

        _ => {
            let auth = Arc::new(auth::NoAuth) as Arc<_>;
            let server =
                Server::bind_with_concurrency(ctx.bind, ctx.concurrent as u32, auth).await?;
            event_loop(server, ctx.connector).await?;
        }
    }

    Ok(())
}

const MAX_UDP_RELAY_PACKET_SIZE: usize = 1500;

async fn event_loop(
    server: Server<std::io::Result<(bool, Extension)>>,
    connector: Connector,
) -> std::io::Result<()> {
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

async fn handle(
    conn: IncomingConnection<std::io::Result<(bool, Extension)>>,
    connector: Arc<Connector>,
) -> std::io::Result<()> {
    let (conn, res) = conn.authenticate().await?;
    let (res, extension) = res?;

    if !res {
        tracing::info!("authentication failed");
        return Ok(());
    }

    match conn.wait_request().await? {
        ClientConnection::UdpAssociate(associate, _) => {
            handle_s5_upd_associate(associate).await?;
        }
        ClientConnection::Bind(bind, _) => {
            let mut conn = bind
                .reply(Reply::CommandNotSupported, Address::unspecified())
                .await?;
            conn.shutdown().await?;
        }
        ClientConnection::Connect(connect, addr) => {
            let target = match addr {
                Address::DomainAddress(domain, port) => {
                    connector
                        .try_connect_with_domain((domain, port), extension)
                        .await
                }
                Address::SocketAddress(addr) => connector.try_connect(addr, &extension).await,
            };

            if let Ok(mut target) = target {
                let mut conn = connect
                    .reply(Reply::Succeeded, Address::unspecified())
                    .await?;
                let (from_client, from_server) =
                    tokio::io::copy_bidirectional(&mut target, &mut conn).await?;
                tracing::debug!(
                    "client wrote {} bytes and received {} bytes",
                    from_client,
                    from_server
                );
            } else {
                let mut conn = connect
                    .reply(Reply::HostUnreachable, Address::unspecified())
                    .await?;
                conn.shutdown().await?;
            }
        }
    }

    Ok(())
}

async fn handle_s5_upd_associate(
    associate: UdpAssociate<associate::NeedReply>,
) -> std::io::Result<()> {
    // listen on a random port
    let listen_ip = associate.local_addr()?.ip();
    let udp_listener = UdpSocket::bind(SocketAddr::from((listen_ip, 0))).await;

    match udp_listener.and_then(|socket| socket.local_addr().map(|addr| (socket, addr))) {
        Err(err) => {
            let mut conn = associate
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await?;
            conn.shutdown().await?;
            Err(err)
        }
        Ok((listen_udp, listen_addr)) => {
            tracing::info!("[UDP] {listen_addr} listen on");

            let s5_listen_addr = Address::from(listen_addr);
            let mut reply_listener = associate.reply(Reply::Succeeded, s5_listen_addr).await?;

            let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
            let listen_udp = Arc::new(AssociatedUdpSocket::from((listen_udp, buf_size)));

            let zero_addr = SocketAddr::from(([0, 0, 0, 0], 0));

            let incoming_addr = Arc::new(Mutex::new(zero_addr));

            let dispatch_socket = UdpSocket::bind(zero_addr).await?;

            let res = loop {
                tokio::select! {
                    res = async {
                        let buf_size = MAX_UDP_RELAY_PACKET_SIZE - UdpHeader::max_serialized_len();
                        listen_udp.set_max_packet_size(buf_size);

                        let (pkt, frag, dst_addr, src_addr) = listen_udp.recv_from().await?;
                        if frag != 0 {
                            return Err("[UDP] packet fragment is not supported".into());
                        }

                        *incoming_addr.lock().await = src_addr;

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
                        let incoming_addr = *incoming_addr.lock().await;
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
    }
}
