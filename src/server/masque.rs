use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use h3::{
    ConnectionState,
    error::Code,
    ext::Protocol,
    proto::{stream::StreamId, varint::VarInt},
    quic::BidiStream,
    server::RequestStream,
};
use h3_datagram::{
    datagram_handler::{DatagramReader, HandleDatagramsExt},
    quic_traits::RecvDatagram,
};
use http::{
    Request, Response, StatusCode,
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
};
use quinn::{Endpoint, Incoming, ServerConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig as TlsServerConfig;
use tokio::{
    net::UdpSocket,
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use super::{AuthMode, Context, Handle, Server, http::genca};
use crate::{connect::Connector, ext::Extension};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UDP_PAYLOAD: usize = 1_500;
const DATAGRAM_CAPSULE_TYPE: u64 = 0;
const MAX_CAPSULE_DATAGRAM_SIZE: usize = MAX_UDP_PAYLOAD + 8;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Sessions = Arc<RwLock<HashMap<StreamId, Arc<Session>>>>;

pub struct MasqueServer {
    endpoint: Endpoint,
    auth: Arc<AuthMode>,
    connector: Arc<Connector>,
    connection_limit: Arc<Semaphore>,
}

struct SessionRegistration {
    sessions: Sessions,
    stream_id: StreamId,
}

struct Session {
    socket: Arc<UdpSocket>,
    signal: mpsc::UnboundedSender<TunnelSignal>,
}

enum TunnelSignal {
    DatagramError,
    SocketError,
}

struct AbortOnDrop<T>(JoinHandle<T>);

enum CapsuleState {
    Header {
        bytes: [u8; 16],
        length: usize,
    },
    Payload {
        capsule_type: u64,
        remaining: u64,
        datagram: Option<BytesMut>,
    },
}

struct CapsuleDecoder {
    state: CapsuleState,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self {
            state: CapsuleState::Header {
                bytes: [0; 16],
                length: 0,
            },
        }
    }
}

impl CapsuleDecoder {
    fn push(&mut self, input: &[u8]) -> io::Result<Vec<Bytes>> {
        let mut datagrams = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            match &mut self.state {
                CapsuleState::Header { bytes, length } => {
                    bytes[*length] = input[offset];
                    *length += 1;
                    offset += 1;
                    if let Some((capsule_type, capsule_length)) =
                        decode_capsule_header(&bytes[..*length])
                    {
                        if capsule_length == 0 {
                            if capsule_type == DATAGRAM_CAPSULE_TYPE {
                                datagrams.push(Bytes::new());
                            }
                            self.state = CapsuleState::default_header();
                            continue;
                        }
                        let datagram = (capsule_type == DATAGRAM_CAPSULE_TYPE
                            && capsule_length <= MAX_CAPSULE_DATAGRAM_SIZE as u64)
                            .then(|| BytesMut::with_capacity(capsule_length as usize));
                        self.state = CapsuleState::Payload {
                            capsule_type,
                            remaining: capsule_length,
                            datagram,
                        };
                    } else if *length == bytes.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid capsule header",
                        ));
                    }
                }
                CapsuleState::Payload {
                    capsule_type,
                    remaining,
                    datagram,
                } => {
                    let amount = usize::try_from((*remaining).min((input.len() - offset) as u64))
                        .map_err(io::Error::other)?;
                    if let Some(datagram) = datagram {
                        datagram.extend_from_slice(&input[offset..offset + amount]);
                    }
                    offset += amount;
                    *remaining -= amount as u64;
                    if *remaining == 0 {
                        if *capsule_type == DATAGRAM_CAPSULE_TYPE
                            && let Some(datagram) = datagram.take()
                        {
                            datagrams.push(datagram.freeze());
                        }
                        self.state = CapsuleState::default_header();
                    }
                }
            }
        }
        Ok(datagrams)
    }

    fn finish(&self) -> io::Result<()> {
        match self.state {
            CapsuleState::Header { length: 0, .. } => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated capsule",
            )),
        }
    }
}

impl CapsuleState {
    fn default_header() -> Self {
        Self::Header {
            bytes: [0; 16],
            length: 0,
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl SessionRegistration {
    fn insert(sessions: Sessions, stream_id: StreamId, session: Arc<Session>) -> Self {
        sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(stream_id, session);
        Self {
            sessions,
            stream_id,
        }
    }
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        self.sessions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.stream_id);
    }
}

impl MasqueServer {
    pub fn new(
        ctx: Context,
        tls_cert: Option<PathBuf>,
        tls_key: Option<PathBuf>,
    ) -> io::Result<Self> {
        let (cert, key) = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => (std::fs::read(cert)?, std::fs::read(key)?),
            _ => genca::get_self_signed_cert().map_err(io::Error::other)?,
        };
        let endpoint = Endpoint::server(server_config(&cert, &key)?, ctx.bind)?;
        let concurrent = usize::try_from(ctx.concurrent)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid connection limit"))?;
        Ok(Self {
            endpoint,
            auth: Arc::new(ctx.auth),
            connector: Arc::new(ctx.connector),
            connection_limit: Arc::new(Semaphore::new(concurrent)),
        })
    }
}

impl Server for MasqueServer {
    async fn start(self, handle: Handle) -> io::Result<()> {
        tracing::info!(
            "HTTP/3 CONNECT-UDP proxy server listening on {}",
            self.endpoint.local_addr()?
        );
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::debug!("[MASQUE] connection task failed: {error}");
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };
                    let Ok(permit) = self.connection_limit.clone().try_acquire_owned() else {
                        incoming.refuse();
                        continue;
                    };
                    let auth = self.auth.clone();
                    let connector = self.connector.clone();
                    let connection_handle = handle.clone();
                    connections.spawn_on(async move {
                        let _permit = permit;
                        if let Err(error) =
                            serve_incoming(incoming, auth, connector, connection_handle).await
                        {
                            tracing::debug!("[MASQUE] connection failed: {error}");
                        }
                    }, &pingora_runtime::current_handle());
                }
            }
        }

        self.endpoint.set_server_config(None);
        if timeout(SHUTDOWN_TIMEOUT, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::debug!("[MASQUE] connection drain timed out");
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        self.endpoint.close(0u32.into(), b"server shutdown");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

fn server_config(cert: &[u8], key: &[u8]) -> io::Result<ServerConfig> {
    let mut cert_reader = cert;
    let certificate_chain =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = key;
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key found"))?;
    let mut tls =
        TlsServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(io::Error::other)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(io::Error::other)?,
        ))
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(100u32.into());
    let crypto = QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn serve_incoming(
    incoming: Incoming,
    auth: Arc<AuthMode>,
    connector: Arc<Connector>,
    handle: Handle,
) -> Result<(), BoxError> {
    let connection = tokio::select! {
        _ = handle.wait_graceful_shutdown() => return Ok(()),
        connection = timeout(HANDSHAKE_TIMEOUT, incoming) => connection??,
    };
    let raw_connection = connection.clone();
    let mut builder = h3::server::builder();
    // RFC 9298 requires both extended CONNECT and HTTP Datagram support.
    // https://www.rfc-editor.org/rfc/rfc9298.html#section-3
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut h3_connection = tokio::select! {
        _ = handle.wait_graceful_shutdown() => return Ok(()),
        connection = timeout(
            HANDSHAKE_TIMEOUT,
            builder.build(h3_quinn::Connection::new(connection)),
        ) => connection??,
    };
    let sessions = Sessions::default();
    let mut datagram_task = AbortOnDrop(pingora_runtime::current_handle().spawn(
        process_datagrams(h3_connection.get_datagram_reader(), sessions.clone()),
    ));
    let mut tunnels = JoinSet::new();

    let mut graceful = false;
    let result = async {
        loop {
            let resolver = tokio::select! {
                _ = handle.wait_graceful_shutdown() => {
                    graceful = true;
                    h3_connection.shutdown(0).await?;
                    break Ok(());
                }
                result = h3_connection.accept() => result?,
                result = &mut datagram_task.0 => {
                    break match result {
                        Ok(result) => result,
                        Err(error) => Err(Box::new(error) as BoxError),
                    };
                }
                result = tunnels.join_next(), if !tunnels.is_empty() => {
                    if let Some(Ok(Err(error))) = result {
                        tracing::debug!("[MASQUE] tunnel failed: {error}");
                    }
                    continue;
                }
            };
            let Some(resolver) = resolver else {
                break Ok(());
            };
            let (request, mut stream) =
                timeout(REQUEST_TIMEOUT, resolver.resolve_request()).await??;
            let Some(extension) = authenticate(&auth, &request).await else {
                reject_authentication(&mut stream).await?;
                continue;
            };
            tunnels.spawn(handle_request(
                request,
                stream,
                raw_connection.clone(),
                sessions.clone(),
                connector.clone(),
                extension,
                handle.clone(),
            ));
        }
    }
    .await;

    if graceful {
        while tunnels.join_next().await.is_some() {}
    } else {
        tunnels.abort_all();
    }
    drop(datagram_task);
    raw_connection.close(0u32.into(), b"proxy connection finished");
    result
}

async fn handle_request<T>(
    request: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    connection: quinn::Connection,
    sessions: Sessions,
    connector: Arc<Connector>,
    extension: Extension,
    handle: Handle,
) -> Result<(), BoxError>
where
    T: BidiStream<Bytes> + Send + 'static,
{
    let Some(target) = requested_target(&request) else {
        return reject_request(&mut stream).await;
    };
    let connect_timeout = connector.connect_timeout();
    let targets = match timeout(connect_timeout, tokio::net::lookup_host(&target)).await {
        Err(_) => return reject_proxy_error(&mut stream, ProxyError::DnsTimeout).await,
        Ok(Err(_)) => return reject_proxy_error(&mut stream, ProxyError::DnsError).await,
        Ok(Ok(targets)) => targets.collect::<Vec<_>>(),
    };
    if targets.is_empty() {
        return reject_proxy_error(&mut stream, ProxyError::DnsError).await;
    }
    let socket = match timeout(connect_timeout, connector.udp(extension).connect(&targets)).await {
        Err(_) => {
            return reject_proxy_error(&mut stream, ProxyError::ConnectionTimeout).await;
        }
        Ok(Ok(socket)) => Arc::new(socket),
        Ok(Err(error)) => {
            return reject_proxy_error(&mut stream, ProxyError::from_io(&error)).await;
        }
    };
    run_tunnel(stream, connection, sessions, socket, handle).await
}

async fn authenticate(auth: &AuthMode, request: &Request<()>) -> Option<Extension> {
    let (Some(username), Some(password)) = (&auth.username, &auth.password) else {
        return Some(Extension::default());
    };
    let value = request
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok())?;
    let (auth_username, auth_password) = value.rsplit_once(':')?;
    if !auth_username.starts_with(username) || auth_password != password {
        return None;
    }
    Extension::try_from(username, auth_username).await.ok()
}

fn requested_target(request: &Request<()>) -> Option<(String, u16)> {
    if request.method() != http::Method::CONNECT
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP)
        || request.uri().scheme_str() != Some("https")
        || request.uri().authority().is_none()
        || request.uri().query().is_some()
        || !uses_capsule_protocol(request)
    {
        return None;
    }
    let target = request
        .uri()
        .path()
        .strip_prefix("/.well-known/masque/udp/")?
        .strip_suffix('/')?;
    let (host, port) = target.rsplit_once('/')?;
    let host = percent_encoding::percent_decode_str(host)
        .decode_utf8()
        .ok()?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() || port == 0 || host.contains('%') {
        return None;
    }
    Some((host.into_owned(), port))
}

fn uses_capsule_protocol(request: &Request<()>) -> bool {
    let mut values = request.headers().get_all("capsule-protocol").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().ok().is_some_and(|value| {
        let value = value.trim();
        value == "?1"
            || value
                .strip_prefix("?1")
                .is_some_and(|rest| rest.starts_with(';'))
    })
}

async fn reject_authentication<T>(stream: &mut RequestStream<T, Bytes>) -> Result<(), BoxError>
where
    T: BidiStream<Bytes>,
{
    let response = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(
            PROXY_AUTHENTICATE,
            r#"Basic realm="vproxy", charset="UTF-8""#,
        )
        .body(())?;
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

async fn reject_request<T>(stream: &mut RequestStream<T, Bytes>) -> Result<(), BoxError>
where
    T: BidiStream<Bytes>,
{
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum ProxyError {
    DnsTimeout,
    DnsError,
    DestinationIpUnroutable,
    ConnectionRefused,
    ConnectionTimeout,
    DestinationUnavailable,
}

impl ProxyError {
    fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable => Self::DestinationIpUnroutable,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut => Self::ConnectionTimeout,
            _ => Self::DestinationUnavailable,
        }
    }

    fn response(self) -> (StatusCode, &'static str) {
        match self {
            Self::DnsTimeout => (StatusCode::GATEWAY_TIMEOUT, "dns_timeout"),
            Self::DnsError => (StatusCode::BAD_GATEWAY, "dns_error"),
            Self::DestinationIpUnroutable => (StatusCode::BAD_GATEWAY, "destination_ip_unroutable"),
            Self::ConnectionRefused => (StatusCode::BAD_GATEWAY, "connection_refused"),
            Self::ConnectionTimeout => (StatusCode::GATEWAY_TIMEOUT, "connection_timeout"),
            Self::DestinationUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "destination_unavailable")
            }
        }
    }
}

async fn reject_proxy_error<T>(
    stream: &mut RequestStream<T, Bytes>,
    error: ProxyError,
) -> Result<(), BoxError>
where
    T: BidiStream<Bytes>,
{
    let (status, error) = error.response();
    stream
        .send_response(
            Response::builder()
                .status(status)
                // RFC 9209 defines Proxy-Status as a Structured Field List.
                // https://www.rfc-editor.org/rfc/rfc9209.html#section-2
                .header("proxy-status", format!("vproxy; error={error}"))
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    Ok(())
}

async fn run_tunnel<T>(
    mut stream: RequestStream<T, Bytes>,
    connection: quinn::Connection,
    sessions: Sessions,
    socket: Arc<UdpSocket>,
    handle: Handle,
) -> Result<(), BoxError>
where
    T: BidiStream<Bytes> + Send + 'static,
{
    let target = socket.peer_addr()?;
    let stream_id = stream.id();
    let (signal, mut signals) = mpsc::unbounded_channel();
    let session = Arc::new(Session {
        socket: socket.clone(),
        signal,
    });
    let _registration = SessionRegistration::insert(sessions, stream_id, session);
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("capsule-protocol", "?1")
                .body(())?,
        )
        .await?;

    // RFC 9298 forbids the proxy from fragmenting UDP payloads. One extra byte
    // lets recv detect and discard datagrams above the common Ethernet MTU.
    // https://www.rfc-editor.org/rfc/rfc9298.html#section-6
    let mut payload = [0; MAX_UDP_PAYLOAD + 1];
    let mut capsules = CapsuleDecoder::default();
    loop {
        tokio::select! {
            _ = handle.wait_graceful_shutdown() => {
                stream.finish().await?;
                return Ok(());
            }
            signal = signals.recv() => {
                match signal {
                    Some(TunnelSignal::DatagramError) => {
                        stream.stop_stream(Code::H3_DATAGRAM_ERROR);
                    }
                    Some(TunnelSignal::SocketError) | None => {
                        stream.finish().await?;
                    }
                }
                return Ok(());
            }
            data = stream.recv_data() => {
                let Some(data) = data? else {
                    if capsules.finish().is_err() {
                        stream.stop_stream(Code::H3_DATAGRAM_ERROR);
                    }
                    return Ok(());
                };
                for datagram in capsules.push(data.chunk()).inspect_err(|_| {
                    stream.stop_stream(Code::H3_DATAGRAM_ERROR);
                })? {
                    if let Err(error) = forward_capsule_datagram(&socket, &datagram).await {
                        if error.kind() == io::ErrorKind::InvalidData {
                            stream.stop_stream(Code::H3_DATAGRAM_ERROR);
                        }
                        return Err(error.into());
                    }
                }
            }
            received = socket.recv(&mut payload) => {
                let length = match received {
                    Ok(length) => length,
                    Err(error) if is_oversized_datagram_error(&error) => continue,
                    Err(error) => {
                        stream.finish().await?;
                        return Err(error.into());
                    }
                };
                let Some(payload) = usable_udp_payload(&payload, length) else {
                    tracing::trace!("[MASQUE] dropping oversized UDP datagram from {target}");
                    continue;
                };
                tracing::trace!("[MASQUE] received {length} UDP bytes from {target}");
                let datagram = encode_target_datagram(stream_id, payload)?;
                match (
                    stream.settings().enable_datagram(),
                    connection.max_datagram_size(),
                ) {
                    (true, Some(maximum)) if datagram.len() <= maximum => {
                        match connection.send_datagram(datagram) {
                            Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    (true, Some(_)) => {}
                    _ => stream.send_data(encode_datagram_capsule(payload)?).await?,
                }
            }
        }
    }
}

fn encode_datagram_capsule(payload: &[u8]) -> io::Result<Bytes> {
    let capsule_length = VarInt::from_u64((1 + payload.len()) as u64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "capsule payload too large"))?;
    let mut capsule = BytesMut::with_capacity(1 + capsule_length.size() + 1 + payload.len());
    capsule.extend_from_slice(&[DATAGRAM_CAPSULE_TYPE as u8]);
    capsule_length.encode(&mut capsule);
    capsule.extend_from_slice(&[0]);
    capsule.extend_from_slice(payload);
    Ok(capsule.freeze())
}

async fn forward_capsule_datagram(socket: &UdpSocket, datagram: &[u8]) -> io::Result<()> {
    let Some((context_id, payload)) = decode_varint(datagram) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing CONNECT-UDP context ID",
        ));
    };
    if context_id != 0 || payload.len() > MAX_UDP_PAYLOAD {
        return Ok(());
    }
    match socket.send(payload).await {
        Ok(_) => Ok(()),
        Err(error) if is_oversized_datagram_error(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn decode_capsule_header(data: &[u8]) -> Option<(u64, u64)> {
    let (capsule_type, type_length) = decode_varint_length(data)?;
    let (capsule_length, _) = decode_varint_length(&data[type_length..])?;
    Some((capsule_type, capsule_length))
}

fn is_oversized_datagram_error(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        #[cfg(windows)]
        {
            code == 10040
        }
        #[cfg(not(windows))]
        {
            code == 90
        }
    })
}

fn encode_target_datagram(stream_id: StreamId, payload: &[u8]) -> io::Result<Bytes> {
    // RFC 9297 prefixes an HTTP Datagram with the request's Quarter Stream ID.
    // https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
    let quarter_stream_id = VarInt::from_u64(stream_id.index())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid request stream ID"))?;
    let mut datagram = BytesMut::with_capacity(quarter_stream_id.size() + 1 + payload.len());
    quarter_stream_id.encode(&mut datagram);
    // RFC 9298 reserves Context ID 0 for the connected UDP target.
    datagram.extend_from_slice(&[0]);
    datagram.extend_from_slice(payload);
    Ok(datagram.freeze())
}

fn usable_udp_payload(payload: &[u8], length: usize) -> Option<&[u8]> {
    (length <= MAX_UDP_PAYLOAD).then(|| &payload[..length])
}

async fn process_datagrams<H>(
    mut reader: DatagramReader<H>,
    sessions: Sessions,
) -> Result<(), BoxError>
where
    H: RecvDatagram + Send + 'static,
    H::Buffer: Send,
{
    loop {
        let datagram = reader.read_datagram().await?;
        let stream_id = datagram.stream_id();
        let payload = datagram.into_payload();
        let session = sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&stream_id)
            .cloned();
        let Some(session) = session else {
            continue;
        };
        let Some((context_id, payload)) = decode_varint(payload.chunk()) else {
            let _ = session.signal.send(TunnelSignal::DatagramError);
            continue;
        };
        if context_id != 0 {
            continue;
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            continue;
        }
        tracing::trace!(
            "[MASQUE] forwarding {} UDP bytes for stream {stream_id:?}",
            payload.len()
        );
        if let Err(error) = session.socket.send(payload).await
            && !is_oversized_datagram_error(&error)
        {
            let _ = session.signal.send(TunnelSignal::SocketError);
        }
    }
}

fn decode_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let (value, length) = decode_varint_length(data)?;
    Some((value, &data[length..]))
}

fn decode_varint_length(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let length = 1usize << (first >> 6);
    if data.len() < length {
        return None;
    }
    let value = data[1..length]
        .iter()
        .fold(u64::from(first & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    Some((value, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authentication_preserves_username_session_extension() {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode("user-session-client-a:password");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION, format!("Basic {credentials}"))
            .body(())
            .expect("valid request");
        let auth = AuthMode {
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
        };

        assert!(matches!(
            authenticate(&auth, &request).await,
            Some(Extension::Session(_))
        ));
    }

    #[tokio::test]
    async fn authentication_rejects_an_invalid_password() {
        let credentials = base64::engine::general_purpose::STANDARD.encode("user:wrong");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION, format!("Basic {credentials}"))
            .body(())
            .expect("valid request");
        let auth = AuthMode {
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
        };

        assert!(authenticate(&auth, &request).await.is_none());
    }

    #[test]
    fn connect_udp_requires_the_https_scheme() {
        let request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("quic://proxy.example/.well-known/masque/udp/target.example/443/")
            .extension(Protocol::CONNECT_UDP)
            .header("capsule-protocol", "?1")
            .body(())
            .expect("valid HTTP request");
        assert!(requested_target(&request).is_none());
    }

    #[test]
    fn capsule_decoder_handles_fragmentation_and_skips_unknown_types() {
        let mut encoded = BytesMut::new();
        encoded.extend_from_slice(&[0x17, 3, 1, 2, 3]);
        encoded.extend_from_slice(&[DATAGRAM_CAPSULE_TYPE as u8, 4, 0]);
        encoded.extend_from_slice(b"udp");

        let mut decoder = CapsuleDecoder::default();
        let mut datagrams = Vec::new();
        for byte in encoded {
            datagrams.extend(decoder.push(&[byte]).expect("valid capsule byte"));
        }
        decoder.finish().expect("complete capsule stream");
        assert_eq!(datagrams, vec![Bytes::from_static(b"\0udp")]);
    }

    #[test]
    fn capsule_decoder_rejects_a_truncated_capsule() {
        let mut decoder = CapsuleDecoder::default();
        assert!(
            decoder
                .push(&[0, 4, 0, 1])
                .expect("valid prefix")
                .is_empty()
        );
        assert!(decoder.finish().is_err());
    }

    #[test]
    fn datagram_capsule_encodes_zero_context() {
        assert_eq!(
            encode_datagram_capsule(b"udp")
                .expect("valid capsule")
                .as_ref(),
            b"\0\x04\0udp"
        );
    }

    #[test]
    fn target_datagram_uses_quarter_stream_id_and_zero_context() {
        let stream_id = StreamId::try_from(4).expect("valid request stream ID");
        let datagram = encode_target_datagram(stream_id, b"payload").expect("valid datagram");
        assert_eq!(datagram.as_ref(), b"\x01\x00payload");
    }

    #[test]
    fn decodes_context_varint_without_panicking_on_truncation() {
        assert_eq!(decode_varint(&[]), None);
        assert_eq!(decode_varint(&[0x40]), None);
        assert_eq!(decode_varint(&[0, 1]), Some((0, &[1][..])));
    }

    #[test]
    fn capsule_protocol_accepts_boolean_parameters_but_not_lists() {
        let request = Request::builder()
            .header("capsule-protocol", "?1; version=1")
            .body(())
            .expect("valid request");
        assert!(uses_capsule_protocol(&request));

        let request = Request::builder()
            .header("capsule-protocol", "?1, ?1")
            .body(())
            .expect("valid request");
        assert!(!uses_capsule_protocol(&request));
    }

    #[test]
    fn drops_udp_payloads_above_the_proxy_limit() {
        let payload = [0; MAX_UDP_PAYLOAD + 1];
        assert_eq!(
            usable_udp_payload(&payload, MAX_UDP_PAYLOAD)
                .expect("payload at the limit is accepted")
                .len(),
            MAX_UDP_PAYLOAD
        );
        assert!(usable_udp_payload(&payload, MAX_UDP_PAYLOAD + 1).is_none());
    }
}
