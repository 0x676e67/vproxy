use std::{
    collections::HashMap,
    future::poll_fn,
    io,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::FutureExt;
use h3::{
    ConnectionState,
    error::{Code, StreamError},
    ext::Protocol,
    proto::{stream::StreamId, varint::VarInt},
    quic::{BidiStream, RecvStream as _, SendStream as _},
    server::RequestStream,
};
use h3_datagram::{
    datagram_handler::{DatagramReader, HandleDatagramsExt},
    quic_traits::RecvDatagram,
};
use http::{
    Request, Response, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, PROXY_AUTHENTICATE, TRANSFER_ENCODING},
};
use quinn::{Endpoint, Incoming, ServerConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig as TlsServerConfig;
use sfv::{BareItem, Item, Parser};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

#[cfg(test)]
use tokio::time::Instant;

use super::{
    Context, Handle, MAX_UDP_RELAY_PAYLOAD_SIZE, Server,
    auth::{self, Authenticated, Service, Source, basic_credentials},
    drain_connections,
    http::genca,
    is_oversized_datagram_error,
};
use crate::connect::Connector;

#[cfg(feature = "management")]
use crate::traffic::{Data, Direction, Meter};

// Only outgoing DATA carries payload meters. The h3-quinn receive buffer stays
// Bytes, and control/HEADERS frames must not acquire one request's identity.
#[cfg(feature = "management")]
type ResponseData = Data<Bytes>;
#[cfg(not(feature = "management"))]
type ResponseData = Bytes;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
// RFC 9114 section 5.2 permits omitting GOAWAY after all request IDs are used.
const MAX_REQUEST_STREAM_ID: u64 = (1_u64 << 62) - 4;
const DATAGRAM_CAPSULE_TYPE: u64 = 0;
const MAX_CAPSULE_DATAGRAM_SIZE: usize = MAX_UDP_RELAY_PAYLOAD_SIZE + 8;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Sessions = Arc<RwLock<HashMap<StreamId, Arc<Session>>>>;

pub struct MasqueServer {
    endpoint: Endpoint,
    auth: Arc<Source>,
    connector: Arc<Connector>,
    tunnel_limit: Arc<Semaphore>,
    #[cfg(feature = "management")]
    leaf: Option<rustls_pki_types::CertificateDer<'static>>,
}

struct SessionRegistration {
    sessions: Sessions,
    stream_id: StreamId,
}

struct Session {
    socket: Arc<UdpSocket>,
    signal: mpsc::UnboundedSender<TunnelSignal>,
    // Datagram dispatch may briefly retain a session after stream removal;
    // that work shares the stream's one admission, never a second user slot.
    #[cfg(feature = "management")]
    _lease: Option<Arc<crate::access::FlowLease>>,
    #[cfg(feature = "management")]
    upload: Option<Meter>,
}

struct TunnelContext {
    connection: quinn::Connection,
    sessions: Sessions,
    connector: Arc<Connector>,
    tunnel_limit: Arc<Semaphore>,
    handle: Handle,
}

enum TunnelSignal {
    DatagramError,
    SocketError,
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    /// Normal/error cleanup waits for cancellation to finish. Drop remains only
    /// the fallback when the owning connection future is itself canceled.
    async fn abort_and_join(&mut self) -> Result<T, tokio::task::JoinError> {
        self.0.abort();
        (&mut self.0).await
    }
}

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
    /// The leaf installed in this endpoint's QUIC TLS configuration. Keeping it
    /// on the cold server owner adds nothing to connection or tunnel clones.
    #[cfg(feature = "management")]
    pub(super) fn certificate_leaf(&self) -> Option<&[u8]> {
        self.leaf.as_ref().map(|leaf| leaf.as_ref())
    }

    /// Inspect the actual UDP socket rather than guessing from a TCP probe.
    #[cfg(test)]
    pub(super) fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn new(
        ctx: Context,
        tls_cert: Option<PathBuf>,
        tls_key: Option<PathBuf>,
    ) -> io::Result<Self> {
        let tunnel_limit = super::connection_limit(ctx.concurrent)?;
        let (cert, key) = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => (std::fs::read(cert)?, std::fs::read(key)?),
            _ => genca::get_self_signed_cert().map_err(io::Error::other)?,
        };
        let config = configured_server_config(&cert, &key)?;
        Self::bind_configured(ctx, tunnel_limit, config)
    }

    /// QUIC retains the exact prepared signer while preserving TLS1.3/H3 and
    /// existing transport/admission settings; no PEM path is opened at bind.
    #[cfg(feature = "management")]
    pub(crate) fn from_identity(ctx: Context, identity: super::tls::Identity) -> io::Result<Self> {
        let tunnel_limit = super::connection_limit(ctx.concurrent)?;
        let leaf = identity.leaf().cloned();
        let tls = TlsServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(identity.resolver());
        let config = configured_tls(tls, leaf)?;
        Self::bind_configured(ctx, tunnel_limit, config)
    }

    fn bind_configured(
        ctx: Context,
        tunnel_limit: Arc<Semaphore>,
        config: ConfiguredServer,
    ) -> io::Result<Self> {
        let endpoint = Endpoint::server(config.config, ctx.bind)?;
        Ok(Self {
            endpoint,
            auth: Arc::new(ctx.auth),
            connector: Arc::new(ctx.connector),
            tunnel_limit,
            #[cfg(feature = "management")]
            leaf: config.leaf,
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
        let result = loop {
            tokio::select! {
                _ = handle.wait_graceful_shutdown() => break Ok(()),
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::debug!("[MASQUE] connection task failed: {error}");
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break Ok(());
                    };
                    let auth = self.auth.clone();
                    let connector = self.connector.clone();
                    let tunnel_limit = self.tunnel_limit.clone();
                    let connection_handle = handle.clone();
                    connections.spawn_on(async move {
                        if let Err(error) =
                            serve_incoming(
                                incoming,
                                auth,
                                connector,
                                tunnel_limit,
                                connection_handle,
                            )
                            .await
                        {
                            tracing::debug!("[MASQUE] connection failed: {error}");
                        }
                    }, handle.runtime_handle());
                }
            }
        };

        self.endpoint.set_server_config(None);
        result.and(drain_endpoint(&self.endpoint, &mut connections, &handle).await)
    }
}

/// Maintenance leaves established connections running until the peer closes or
/// the negotiated idle timeout expires. Process stop adds one retained absolute
/// deadline for task completion and QUIC closing; `wait_idle` is not a receipt.
async fn drain_endpoint(
    endpoint: &Endpoint,
    connections: &mut JoinSet<()>,
    handle: &Handle,
) -> io::Result<()> {
    let drained = drain_connections(connections, "MASQUE", handle).await;
    endpoint.close(0u32.into(), b"server shutdown");
    let idle = handle
        .wait_for_drain(endpoint.wait_idle(), Duration::ZERO)
        .await
        .map_err(|error| io::Error::new(error.kind(), "MASQUE endpoint close did not finish"));
    drained.and(idle)
}

type H3Connection = h3::server::Connection<h3_quinn::Connection, ResponseData>;

// Keep the already-owned resolver inline rather than allocating once per
// accepted request solely to shrink this short-lived control-flow value.
#[allow(clippy::large_enum_variant)]
enum RequestEvent {
    Request(h3::server::RequestResolver<h3_quinn::Connection, ResponseData>),
    Rejected,
    Closed,
}

/// h3 0.0.8 uses an inclusive local cutoff, while the GOAWAY wire cutoff is
/// exclusive. One extra ID keeps every previously accepted request below it.
/// Its `accept()` also sends `shutdown(0)` on completion, so a quiescing driver
/// must use the already-enabled backend API instead of lowering that cutoff.
/// https://docs.rs/h3/0.0.8/src/h3/server/connection.rs.html#123-166
/// https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2
async fn begin_quiescence(
    connection: &mut H3Connection,
    last_accepted: Option<StreamId>,
) -> Result<(), h3::error::ConnectionError> {
    if last_accepted.is_none_or(|id| id.into_inner() < MAX_REQUEST_STREAM_ID) {
        connection.shutdown(1).await?;
    }
    Ok(())
}

async fn next_request(
    connection: &mut H3Connection,
    quiescing: bool,
) -> Result<RequestEvent, h3::error::ConnectionError> {
    if !quiescing {
        return connection
            .accept()
            .await
            .map(|request| request.map_or(RequestEvent::Closed, RequestEvent::Request));
    }
    let Some(mut stream) = poll_fn(|cx| connection.poll_accept_request_stream(cx)).await? else {
        return Ok(RequestEvent::Closed);
    };
    // No headers, authentication, or outbound work has been processed. The
    // backend can admit the one stream exactly at its inclusive cutoff; reject
    // it here as well. Do not use its internal request count as a drain receipt.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1
    stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
    stream.reset(Code::H3_REQUEST_REJECTED.value());
    Ok(RequestEvent::Rejected)
}

struct ConfiguredServer {
    config: ServerConfig,
    #[cfg(feature = "management")]
    leaf: Option<rustls_pki_types::CertificateDer<'static>>,
}

// Existing QUIC fixtures customize transport after creating the same config.
#[cfg(test)]
fn server_config(cert: &[u8], key: &[u8]) -> io::Result<ServerConfig> {
    configured_server_config(cert, key).map(|loaded| loaded.config)
}

fn configured_server_config(cert: &[u8], key: &[u8]) -> io::Result<ConfiguredServer> {
    let mut cert_reader = cert;
    let certificate_chain =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "management")]
    let leaf = certificate_chain.first().cloned();
    let mut key_reader = key;
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key found"))?;
    let tls = TlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(certificate_chain, private_key)
    .map_err(io::Error::other)?;
    configured_tls(
        tls,
        #[cfg(feature = "management")]
        leaf,
    )
}

fn configured_tls(
    mut tls: TlsServerConfig,
    #[cfg(feature = "management")] leaf: Option<rustls_pki_types::CertificateDer<'static>>,
) -> io::Result<ConfiguredServer> {
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
    Ok(ConfiguredServer {
        config,
        #[cfg(feature = "management")]
        leaf,
    })
}

async fn serve_incoming(
    incoming: Incoming,
    auth: Arc<Source>,
    connector: Arc<Connector>,
    tunnel_limit: Arc<Semaphore>,
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
    let mut datagram_task = AbortOnDrop(handle.runtime_handle().spawn(process_datagrams(
        h3_connection.get_datagram_reader(),
        sessions.clone(),
    )));
    let tunnel_context = Arc::new(TunnelContext {
        connection: raw_connection.clone(),
        sessions,
        connector,
        tunnel_limit,
        handle: handle.clone(),
    });
    let mut tunnels = JoinSet::new();

    let mut graceful = false;
    let mut datagram_finished = false;
    let mut quiescing = false;
    let mut accepting = true;
    let mut last_accepted = None;
    let result = async {
        loop {
            let request = tokio::select! {
                _ = handle.wait_graceful_shutdown(), if !quiescing => {
                    begin_quiescence(&mut h3_connection, last_accepted).await?;
                    if handle.is_quiescing() {
                        quiescing = true;
                        continue;
                    }
                    graceful = true;
                    break Ok(());
                }
                _ = handle.wait_stopping(), if quiescing => {
                    graceful = true;
                    break Ok(());
                }
                result = next_request(&mut h3_connection, quiescing), if accepting => result?,
                _ = raw_connection.closed(), if quiescing && !accepting => break Ok(()),
                result = &mut datagram_task.0 => {
                    datagram_finished = true;
                    break match result {
                        Ok(result) => result,
                        Err(error) => Err(Box::new(error) as BoxError),
                    };
                }
                result = tunnels.join_next(), if !tunnels.is_empty() => {
                    match result {
                        Some(Ok(Err(error))) => tracing::debug!("[MASQUE] tunnel failed: {error}"),
                        Some(Err(error)) => return Err(io::Error::other(error).into()),
                        _ => {}
                    }
                    continue;
                }
            };
            let resolver = match request {
                RequestEvent::Request(resolver) => resolver,
                RequestEvent::Rejected => continue,
                RequestEvent::Closed if quiescing => {
                    // Dropping h3's driver immediately closes Quinn. Retain it
                    // even after the last application task finishes, so queued
                    // reliable Capsules can still be transmitted. h3-quinn's
                    // finish is not a peer ACK and exposes no stopped() handle.
                    // https://docs.rs/h3-quinn/0.0.10/src/h3_quinn/lib.rs.html#479-487
                    accepting = false;
                    continue;
                }
                RequestEvent::Closed => break Ok(()),
            };
            last_accepted = Some(resolver.frame_stream.id());
            let (request, mut stream) =
                match timeout(REQUEST_TIMEOUT, resolver.resolve_request()).await? {
                    Ok(request) => request,
                    // Cancellation is scoped to this request, including incomplete HEADERS.
                    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1
                    Err(error @ StreamError::RemoteTerminate { .. }) => {
                        tracing::debug!("[MASQUE] request canceled before headers: {error}");
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
            // Resolving fragmented HEADERS can outlive the admission change.
            // This check is the dispatch boundary, before authentication can
            // acquire a managed lease or any request can open an outbound UDP
            // socket. A process-stop request also rejects such unstarted work.
            if handle.wait_graceful_shutdown().now_or_never().is_some() {
                stream.stop_sending(Code::H3_REQUEST_REJECTED);
                stream.stop_stream(Code::H3_REQUEST_REJECTED);
                continue;
            }
            let authenticated = match authenticate(&auth, &request).await {
                Ok(authenticated) => authenticated,
                Err(error) => {
                    match reject_authentication(&mut stream, error).await {
                        Ok(()) => {}
                        // A peer can stop receiving the 407 while it is being written.
                        Err(error @ StreamError::RemoteTerminate { .. }) => {
                            tracing::debug!("[MASQUE] authentication response canceled: {error}");
                        }
                        Err(error) => return Err(error.into()),
                    }
                    continue;
                }
            };
            if handle.wait_graceful_shutdown().now_or_never().is_some() {
                // Authentication may have waited for a worker while the mode
                // changed. Release its lease before outbound dispatch. Since
                // the upper layer has processed credentials, do not advertise
                // this request as never processed/retryable.
                // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                continue;
            }
            tunnels.spawn(handle_request(
                request,
                stream,
                tunnel_context.clone(),
                authenticated,
            ));
        }
    }
    .await;

    let tunnels = reap_tunnels(&mut tunnels, graceful)
        .await
        .map_err(Into::into);
    // A JoinHandle's delivered output cannot be awaited a second time. Ordinary
    // peer closure may already have completed the datagram branch above.
    let datagram = if datagram_finished {
        Ok(())
    } else {
        match datagram_task.abort_and_join().await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(Box::new(error) as BoxError),
        }
    };
    raw_connection.close(0u32.into(), b"proxy connection finished");
    result.and(tunnels).and(datagram)
}

/// On normal/error returns, release every owned tunnel before the connection
/// completes. An outer listener timeout can still cancel this cleanup; its
/// JoinSet/AbortOnDrop fallback requests cancellation, and runtime teardown is
/// the final ownership barrier in that case, not this listener's return value.
async fn reap_tunnels(
    tunnels: &mut JoinSet<Result<(), BoxError>>,
    graceful: bool,
) -> io::Result<()> {
    if !graceful {
        tunnels.abort_all();
    }
    let mut failure = None;
    while let Some(result) = tunnels.join_next().await {
        match result {
            Ok(Err(error)) => tracing::debug!("[MASQUE] tunnel failed while closing: {error}"),
            Err(error) if graceful || !error.is_cancelled() => {
                failure.get_or_insert_with(|| io::Error::other(error));
            }
            _ => {}
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn handle_request<T>(
    request: Request<()>,
    mut stream: RequestStream<T, ResponseData>,
    context: Arc<TunnelContext>,
    authenticated: Authenticated,
) -> Result<(), BoxError>
where
    T: BidiStream<ResponseData> + Send + 'static,
{
    let Some(target) = requested_target(&request) else {
        return reject_request(&mut stream).await;
    };
    let permit = match context.tunnel_limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return reject_proxy_error(&mut stream, ProxyError::ConnectionLimitReached).await;
        }
    };
    let connect_timeout = context.connector.connect_timeout();
    let targets = match timeout(connect_timeout, tokio::net::lookup_host(&target)).await {
        Err(_) => return reject_proxy_error(&mut stream, ProxyError::DnsTimeout).await,
        Ok(Err(_)) => return reject_proxy_error(&mut stream, ProxyError::DnsError).await,
        Ok(Ok(targets)) => targets.collect::<Vec<_>>(),
    };
    if targets.is_empty() {
        return reject_proxy_error(&mut stream, ProxyError::DnsError).await;
    }
    let selected_connector = authenticated
        .source
        .map(|source| context.connector.as_ref().clone().with_source(Some(source)));
    let connector = selected_connector
        .as_ref()
        .unwrap_or(context.connector.as_ref());
    let socket = match timeout(
        connect_timeout,
        connector.udp(authenticated.extension).connect(&targets),
    )
    .await
    {
        Err(_) => {
            return reject_proxy_error(&mut stream, ProxyError::ConnectionTimeout).await;
        }
        Ok(Ok(socket)) => Arc::new(socket),
        Ok(Err(error)) => {
            return reject_proxy_error(&mut stream, ProxyError::from_io(&error)).await;
        }
    };
    run_tunnel(
        stream,
        context.connection.clone(),
        context.sessions.clone(),
        socket,
        permit,
        context.handle.clone(),
        authenticated,
    )
    .await
}

async fn authenticate(
    source: &Source,
    request: &Request<()>,
) -> Result<Authenticated, auth::Error> {
    let credentials = source
        .requires_password()
        .then(|| basic_credentials(request.headers()))
        .flatten();
    source
        .authenticate(
            credentials.as_ref().map(|value| value.username()),
            credentials
                .as_ref()
                .map(|value| value.password().as_bytes()),
            Service::Masque,
        )
        .await
}

fn requested_target(request: &Request<()>) -> Option<(String, u16)> {
    if request.method() != http::Method::CONNECT
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP)
        || request.uri().scheme_str() != Some("https")
        || request.uri().authority().is_none()
        || request.uri().query().is_some()
        || [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
            .iter()
            .any(|name| request.headers().contains_key(name))
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
    value
        .to_str()
        .ok()
        .and_then(|value| Parser::new(value).parse::<Item>().ok())
        .is_some_and(|item| item.bare_item == BareItem::Boolean(true))
}

async fn reject_authentication<T>(
    stream: &mut RequestStream<T, ResponseData>,
    error: auth::Error,
) -> Result<(), StreamError>
where
    T: BidiStream<ResponseData>,
{
    let mut response = Response::new(());
    *response.status_mut() = match error {
        auth::Error::InvalidCredentials => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        auth::Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        auth::Error::Denied => StatusCode::FORBIDDEN,
        #[cfg(feature = "management")]
        auth::Error::Capacity => StatusCode::SERVICE_UNAVAILABLE,
    };
    if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            http::HeaderValue::from_static(r#"Basic realm="vproxy", charset="UTF-8""#),
        );
    }
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

async fn reject_request<T>(stream: &mut RequestStream<T, ResponseData>) -> Result<(), BoxError>
where
    T: BidiStream<ResponseData>,
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
    ConnectionLimitReached,
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
            Self::ConnectionLimitReached => {
                (StatusCode::SERVICE_UNAVAILABLE, "connection_limit_reached")
            }
        }
    }
}

async fn reject_proxy_error<T>(
    stream: &mut RequestStream<T, ResponseData>,
    error: ProxyError,
) -> Result<(), BoxError>
where
    T: BidiStream<ResponseData>,
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
    mut stream: RequestStream<T, ResponseData>,
    connection: quinn::Connection,
    sessions: Sessions,
    socket: Arc<UdpSocket>,
    _permit: OwnedSemaphorePermit,
    handle: Handle,
    _authenticated: Authenticated,
) -> Result<(), BoxError>
where
    T: BidiStream<ResponseData> + Send + 'static,
{
    let target = socket.peer_addr()?;
    let stream_id = stream.id();
    let (signal, mut signals) = mpsc::unbounded_channel();
    #[cfg(feature = "management")]
    let upload = _authenticated.meter(Direction::Upload);
    #[cfg(feature = "management")]
    let download = _authenticated.meter(Direction::Download);
    let session = Arc::new(Session {
        socket: socket.clone(),
        signal,
        #[cfg(feature = "management")]
        _lease: _authenticated.lease.clone(),
        #[cfg(feature = "management")]
        upload: upload.clone(),
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
    let mut payload = [0; MAX_UDP_RELAY_PAYLOAD_SIZE + 1];
    let mut capsules = CapsuleDecoder::default();
    loop {
        tokio::select! {
            _ = handle.wait_stopping() => {
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
                    if let Err(error) = forward_capsule_datagram(&socket, &datagram,
                        #[cfg(feature = "management")]
                        upload.as_ref(),
                    ).await {
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
                            Ok(()) => {
                                #[cfg(feature = "management")]
                                if let Some(meter) = &download {
                                    meter.add(payload.len());
                                }
                            }
                            Err(quinn::SendDatagramError::TooLarge) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    (true, Some(_)) => {}
                    _ => {
                        let capsule = encode_datagram_capsule(payload)?;
                        #[cfg(feature = "management")]
                        let capsule = {
                            let metadata = capsule.len().checked_sub(payload.len()).ok_or_else(|| {
                                io::Error::other("encoded capsule is shorter than its payload")
                            })?;
                            Data::prefixed(capsule, metadata, download.clone())?
                        };
                        // Counted DATA excludes both the Capsule metadata and
                        // H3's independent frame header. In h3-quinn it advances
                        // only after Quinn accepts a write, including a prefix
                        // before cancellation or an eventual stream error.
                        stream.send_data(capsule).await?;
                    },
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

async fn forward_capsule_datagram(
    socket: &UdpSocket,
    datagram: &[u8],
    #[cfg(feature = "management")] meter: Option<&Meter>,
) -> io::Result<()> {
    let Some((context_id, payload)) = decode_varint(datagram) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing CONNECT-UDP context ID",
        ));
    };
    if context_id != 0 || payload.len() > MAX_UDP_RELAY_PAYLOAD_SIZE {
        return Ok(());
    }
    match socket.send(payload).await {
        Ok(_length) => {
            #[cfg(feature = "management")]
            if _length == payload.len()
                && let Some(meter) = meter
            {
                meter.add(payload.len());
            }
            Ok(())
        }
        Err(error) if is_oversized_datagram_error(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn decode_capsule_header(data: &[u8]) -> Option<(u64, u64)> {
    let (capsule_type, type_length) = decode_varint_length(data)?;
    let (capsule_length, _) = decode_varint_length(&data[type_length..])?;
    Some((capsule_type, capsule_length))
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
    (length <= MAX_UDP_RELAY_PAYLOAD_SIZE).then(|| &payload[..length])
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
        if payload.len() > MAX_UDP_RELAY_PAYLOAD_SIZE {
            continue;
        }
        tracing::trace!(
            "[MASQUE] forwarding {} UDP bytes for stream {stream_id:?}",
            payload.len()
        );
        match session.socket.send(payload).await {
            Ok(_length) => {
                #[cfg(feature = "management")]
                if _length == payload.len()
                    && let Some(meter) = &session.upload
                {
                    meter.add(payload.len());
                }
            }
            Err(error) if !is_oversized_datagram_error(&error) => {
                let _ = session.signal.send(TunnelSignal::SocketError);
            }
            _ => {}
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
    use base64::Engine;
    use http::header::PROXY_AUTHORIZATION;

    use super::*;
    use crate::{AuthMode, ext::Extension};

    fn connect_udp_request() -> http::request::Builder {
        Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://proxy.example/.well-known/masque/udp/target.example/443/")
            .extension(Protocol::CONNECT_UDP)
            .header("capsule-protocol", "?1")
    }

    #[tokio::test]
    async fn authentication_preserves_username_session_extension() {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode("user-session-client-a:pass:word");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION, format!("bAsIc   {credentials}"))
            .body(())
            .expect("valid request");
        let auth: Source = AuthMode {
            username: Some("user".to_owned()),
            password: Some("pass:word".to_owned()),
        }
        .into();

        assert!(matches!(
            authenticate(&auth, &request).await,
            Ok(Authenticated {
                extension: Extension::Session(_),
                ..
            })
        ));

        let mut duplicate = request;
        duplicate.headers_mut().append(
            PROXY_AUTHORIZATION,
            http::HeaderValue::from_static("Basic dXNlcjpwYXNzOndvcmQ="),
        );
        assert!(authenticate(&auth, &duplicate).await.is_err());
    }

    #[tokio::test]
    async fn authentication_rejects_an_invalid_password() {
        let credentials = base64::engine::general_purpose::STANDARD.encode("user:wrong");
        let request = Request::builder()
            .header(PROXY_AUTHORIZATION, format!("Basic {credentials}"))
            .body(())
            .expect("valid request");
        let auth: Source = AuthMode {
            username: Some("user".to_owned()),
            password: Some("password".to_owned()),
        }
        .into();

        assert!(matches!(
            authenticate(&auth, &request).await,
            Err(auth::Error::InvalidCredentials)
        ));
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
    fn connect_udp_rejects_http_content_fields() {
        for name in [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING] {
            let request = connect_udp_request()
                .header(name, "0")
                .body(())
                .expect("valid HTTP request");
            assert!(requested_target(&request).is_none());
        }
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
    fn capsule_protocol_rejects_false_and_malformed_items() {
        for value in ["?0", "1", "?1;", "?1;==="] {
            let request = Request::builder()
                .header("capsule-protocol", value)
                .body(())
                .expect("valid request");
            assert!(!uses_capsule_protocol(&request), "{value}");
        }
    }

    #[test]
    fn tunnel_limit_counts_streams_instead_of_quic_connections() {
        let limit = Arc::new(Semaphore::new(1));
        let permit = limit
            .clone()
            .try_acquire_owned()
            .expect("first tunnel is admitted");
        assert!(limit.clone().try_acquire_owned().is_err());
        drop(permit);
        assert!(limit.try_acquire_owned().is_ok());
    }

    #[test]
    fn drops_udp_payloads_above_the_proxy_limit() {
        let payload = [0; MAX_UDP_RELAY_PAYLOAD_SIZE + 1];
        assert_eq!(
            usable_udp_payload(&payload, MAX_UDP_RELAY_PAYLOAD_SIZE)
                .expect("payload at the limit is accepted")
                .len(),
            MAX_UDP_RELAY_PAYLOAD_SIZE
        );
        assert!(usable_udp_payload(&payload, MAX_UDP_RELAY_PAYLOAD_SIZE + 1).is_none());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use std::{future::poll_fn, sync::Arc, time::Duration};

    use bytes::{Buf, Bytes};
    use h3::ext::Protocol;
    use http::{Request, StatusCode};
    use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
    use tokio::{net::UdpSocket, time::timeout};

    use super::{CapsuleDecoder, Connector, Handle, Semaphore, encode_datagram_capsule};
    use crate::AuthMode;

    #[tokio::test]
    async fn canceling_unresolved_request_preserves_connection_and_tunnel() {
        cancellation_preserves_tunnel(false, None).await;
    }

    #[tokio::test]
    async fn canceling_authentication_response_preserves_connection_and_tunnel() {
        cancellation_preserves_tunnel(true, None).await;
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_streams_reauthenticate_without_releasing_an_existing_tunnel_lease() {
        use crate::access::{Reader, tests::routed_policy as policy};
        cancellation_preserves_tunnel(true, Some(Reader::new(policy(1, 1)).unwrap())).await;
    }

    #[cfg(feature = "management")]
    type ManagedReader = crate::access::Reader;
    #[cfg(not(feature = "management"))]
    type ManagedReader = ();

    async fn cancellation_preserves_tunnel(
        cancel_authentication: bool,
        _managed: Option<ManagedReader>,
    ) {
        timeout(Duration::from_secs(10), async {
            // The 407 response cannot finish until this client grants more credit.
            let (server, client) = endpoints(16, None);
            let connector = Connector::new(
                None,
                None,
                None,
                5,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            );
            let connector = if _managed.is_some() {
                Connector::new(
                    Some("192.0.2.1/32".parse().unwrap()),
                    None,
                    None,
                    5,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    None,
                )
            } else {
                connector
            };
            let source: super::Source = AuthMode {
                username: Some("test".into()),
                password: Some("test".into()),
            }
            .into();
            let authorization = "Basic dGVzdDp0ZXN0".to_owned();
            #[cfg(feature = "management")]
            let source = if let Some(reader) = &_managed {
                super::Source::Managed(reader.clone())
            } else {
                source
            };
            #[cfg(feature = "management")]
            let authorization = if _managed.is_some() {
                use base64::Engine as _;
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(
                        [
                            crate::access::tests::ROUTED_LOGIN.as_bytes(),
                            b":",
                            &crate::access::tests::secret()
                        ]
                        .concat()
                    )
                )
            } else {
                authorization
            };
            let server_task = tokio::spawn({
                let server = server.clone();
                async move {
                    super::serve_incoming(
                        server.accept().await.unwrap(),
                        Arc::new(source),
                        Arc::new(connector),
                        Arc::new(Semaphore::new(2)),
                        Handle::new(),
                    )
                    .await
                }
            });
            let connection = client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut driver, mut sender) =
                h3::client::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let driver_task =
                tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_addr = udp.local_addr().unwrap();
            let expected_source = if _managed.is_some() {
                "127.0.0.2"
            } else {
                "127.0.0.1"
            }
            .parse::<std::net::IpAddr>()
            .unwrap();
            let echo_task = tokio::spawn(async move {
                let mut buffer = [0; 32];
                for expected in [b"before".as_slice(), b"after".as_slice()] {
                    let (size, peer) = udp.recv_from(&mut buffer).await.unwrap();
                    assert_eq!(peer.ip(), expected_source);
                    assert_eq!(&buffer[..size], expected);
                    udp.send_to(&buffer[..size], peer).await.unwrap();
                }
            });
            let request = Request::connect(format!(
                "https://localhost/.well-known/masque/udp/127.0.0.1/{}/",
                udp_addr.port(),
            ))
            .extension(Protocol::CONNECT_UDP)
            .header("capsule-protocol", "?1")
            .header("proxy-authorization", &authorization)
            .body(())
            .unwrap();
            let mut tunnel = sender.send_request(request).await.unwrap();
            assert_eq!(
                tunnel.recv_response().await.unwrap().status(),
                StatusCode::OK
            );
            let mut decoder = CapsuleDecoder::default();
            for payload in [b"before".as_slice(), b"after".as_slice()] {
                if payload == b"after" {
                    let (mut send, mut recv) = connection.open_bi().await.unwrap();
                    if cancel_authentication {
                        // Static QPACK: GET https://localhost/ without credentials.
                        // RFC 9204 appendix A: indexed :method, :scheme and :path.
                        let fields = b"\x00\x00\xd1\xd7\xc1\x50\x09localhost";
                        send.write_all(&[1, u8::try_from(fields.len()).unwrap()])
                            .await
                            .unwrap();
                        send.write_all(fields).await.unwrap();
                        send.finish().unwrap();
                        let mut byte = [0];
                        recv.read_exact(&mut byte).await.unwrap();
                        assert_eq!(byte, [1], "407 HEADERS started before cancellation");
                        recv.stop(0x10c_u32.into()).unwrap();
                    } else {
                        send.write_all(&[0x01, 0x10, 0x00]).await.unwrap();
                        send.reset(0x10c_u32.into()).unwrap();
                        recv.stop(0x10c_u32.into()).unwrap();
                    }
                    // A later response proves that the accept loop advanced after cancellation.
                    let mut probe = sender
                        .send_request(
                            Request::get("https://localhost/probe")
                                .header("proxy-authorization", &authorization)
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        probe
                            .recv_response()
                            .await
                            .expect("request cancellation closed connection")
                            .status(),
                        if _managed.is_some() {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::BAD_REQUEST
                        }
                    );
                    probe.finish().await.unwrap();
                    #[cfg(feature = "management")]
                    if let Some(reader) = &_managed {
                        let mut disabled = crate::access::tests::routed_policy(2, 1);
                        disabled.users[0].active = false;
                        reader.publish(disabled).unwrap();
                        let mut denied = sender
                            .send_request(
                                Request::get("https://localhost/probe")
                                    .header("proxy-authorization", &authorization)
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        assert_eq!(
                            denied.recv_response().await.unwrap().status(),
                            StatusCode::FORBIDDEN
                        );
                        denied.finish().await.unwrap();
                        reader
                            .publish(crate::access::tests::routed_policy(3, 1))
                            .unwrap();
                    }
                }
                tunnel
                    .send_data(encode_datagram_capsule(payload).unwrap())
                    .await
                    .unwrap();
                loop {
                    let mut data = tunnel
                        .recv_data()
                        .await
                        .unwrap()
                        .expect("tunnel stayed open");
                    let len = data.remaining();
                    let frames = decoder.push(&data.copy_to_bytes(len)).unwrap();
                    if !frames.is_empty() {
                        assert_eq!(frames, vec![Bytes::from([b"\0", payload].concat())]);
                        break;
                    }
                }
            }
            assert!(connection.close_reason().is_none());
            echo_task.await.unwrap();
            tunnel.finish().await.unwrap();
            #[cfg(feature = "management")]
            if let Some(reader) = &_managed {
                loop {
                    match reader.authenticate(
                        crate::access::tests::ROUTED_LOGIN,
                        &crate::access::tests::secret(),
                        crate::access::Protocol::Masque,
                    ) {
                        Ok(admission) => {
                            drop(admission);
                            break;
                        }
                        Err(crate::access::Error::Capacity) => tokio::task::yield_now().await,
                        Err(error) => panic!("unexpected admission error: {error:?}"),
                    }
                }
                let mut new_stream = sender
                    .send_request(
                        Request::get("https://localhost/probe")
                            .header("proxy-authorization", &authorization)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    new_stream.recv_response().await.unwrap().status(),
                    StatusCode::BAD_REQUEST
                );
                new_stream.finish().await.unwrap();
            }
            connection.close(0_u32.into(), b"test complete");
            let _ = driver_task.await.unwrap();
            let _ = server_task.await.unwrap();
            client.wait_idle().await;
            server.close(0_u32.into(), b"test complete");
            server.wait_idle().await;
        })
        .await
        .expect("MASQUE cancellation regression timed out");
    }

    /// Real TLS/QUIC endpoints shared by the cancellation and accounting fixtures.
    /// A fixed MTU is test-only and applies solely to owned loopback packets; it
    /// makes size-drop tests independent of path-MTU discovery scheduling.
    pub(super) fn endpoints(receive_window: u32, fixed_mtu: Option<u16>) -> (Endpoint, Endpoint) {
        endpoints_with_send_window(receive_window, fixed_mtu, None)
    }

    /// A small server queue makes a paused receiver exercise actual write
    /// backpressure instead of merely leaving bytes buffered inside Quinn.
    pub(super) fn endpoints_with_send_window(
        receive_window: u32,
        fixed_mtu: Option<u16>,
        send_window: Option<u64>,
    ) -> (Endpoint, Endpoint) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut config = super::server_config(
            certificate.cert.pem().as_bytes(),
            certificate.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        if let Some(window) = send_window {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .send_window(window);
        }
        if let Some(mtu) = fixed_mtu {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .initial_mtu(mtu)
                .min_mtu(mtu)
                .mtu_discovery_config(None);
        }
        let server = if let Some(mtu) = fixed_mtu {
            fixed_mtu_endpoint(Some(config), mtu)
        } else {
            Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = if let Some(mtu) = fixed_mtu {
            fixed_mtu_endpoint(None, mtu)
        } else {
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        };
        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(receive_window.into());
        if let Some(mtu) = fixed_mtu {
            transport
                .initial_mtu(mtu)
                .min_mtu(mtu)
                .mtu_discovery_config(None);
        }
        client_config.transport_config(Arc::new(transport));
        client.set_default_client_config(client_config);
        (server, client)
    }

    fn fixed_mtu_endpoint(server: Option<quinn::ServerConfig>, mtu: u16) -> Endpoint {
        // Endpoint's default 1472-byte receive ceiling is independent of transport
        // MTU and is advertised to the peer. Raise both ends of this loopback-only
        // fixture, rather than mistaking a locally rejected send for a proxy drop.
        let mut endpoint = quinn::EndpointConfig::default();
        endpoint.max_udp_payload_size(mtu).unwrap();
        Endpoint::new(
            endpoint,
            server,
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod maintenance_tests {
    //! Actual H3 peers exercise maintenance without treating FIN as an ACK.

    use super::*;

    fn server(endpoint: Endpoint) -> MasqueServer {
        MasqueServer {
            endpoint,
            auth: Arc::new(
                crate::AuthMode {
                    username: None,
                    password: None,
                }
                .into(),
            ),
            connector: Arc::new(Connector::new(
                None,
                None,
                None,
                2,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            )),
            tunnel_limit: Arc::new(Semaphore::new(2)),
            #[cfg(feature = "management")]
            leaf: None,
        }
    }

    fn request(port: u16) -> Request<()> {
        Request::connect(format!(
            "https://localhost/.well-known/masque/udp/127.0.0.1/{port}/",
        ))
        .extension(Protocol::CONNECT_UDP)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap()
    }

    async fn varint(stream: &mut quinn::RecvStream) -> u64 {
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes[..1]).await.unwrap();
        let length = 1_usize << (bytes[0] >> 6);
        stream.read_exact(&mut bytes[1..length]).await.unwrap();
        decode_varint(&bytes[..length]).unwrap().0
    }

    async fn control_frame(control: &mut quinn::RecvStream) -> (u64, Vec<u8>) {
        let kind = varint(control).await;
        let length = usize::try_from(varint(control).await).unwrap();
        assert!(length <= 65_536, "bounded test control frame");
        let mut payload = vec![0; length];
        control.read_exact(&mut payload).await.unwrap();
        (kind, payload)
    }

    async fn settings(control: &mut quinn::RecvStream) {
        let (kind, payload) = control_frame(control).await;
        assert_eq!(kind, 4);
        let mut remaining = payload.as_slice();
        let (mut connect, mut datagram) = (false, false);
        while !remaining.is_empty() {
            let (key, rest) = decode_varint(remaining).unwrap();
            let (value, rest) = decode_varint(rest).unwrap();
            match key {
                0x8 => connect = value == 1,
                0x33 => datagram = value == 1,
                _ => {}
            }
            remaining = rest;
        }
        // RFC 9298 section 3.4: receive both settings before Extended CONNECT.
        assert!(connect && datagram);
    }

    async fn goaway(control: &mut quinn::RecvStream) -> u64 {
        let (kind, payload) = control_frame(control).await;
        assert_eq!(kind, 7);
        let (cutoff, remaining) = decode_varint(&payload).unwrap();
        assert!(remaining.is_empty());
        cutoff
    }

    #[tokio::test]
    async fn quiesce_rejects_new_work_but_keeps_the_old_tunnel_and_correct_goaway_cutoff() {
        timeout(Duration::from_secs(10), async {
            let (endpoint, client) = super::cancellation_tests::endpoints(65_536, None);
            let server = server(endpoint);
            let address = server.endpoint.local_addr().unwrap();
            let observation = server.endpoint.clone();
            let slots = server.tunnel_limit.clone();
            let handle = Handle::new();
            let mut task = AbortOnDrop(tokio::spawn(server.start(handle.clone())));
            let connection = client.connect(address, "localhost").unwrap().await.unwrap();
            // The request sender/streams use the real H3 API. Keep its driver owned
            // but unpolled so this test can inspect the actual server control wire;
            // no second consumer competes for its unidirectional control stream.
            let (_driver, mut sender) =
                h3::client::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let mut control = connection.accept_uni().await.unwrap();
            assert_eq!(varint(&mut control).await, 0);
            settings(&mut control).await;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = udp.local_addr().unwrap().port();
            let mut echo = AbortOnDrop(tokio::spawn(async move {
                let mut bytes = [0; 32];
                for expected in [b"before".as_slice(), b"after".as_slice()] {
                    let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
                    assert_eq!(&bytes[..length], expected);
                    udp.send_to(&bytes[..length], peer).await.unwrap();
                }
            }));
            let mut tunnel = sender.send_request(request(port)).await.unwrap();
            assert_eq!(
                tunnel.recv_response().await.unwrap().status(),
                StatusCode::OK
            );
            let accepted_id = tunnel.id().into_inner();
            let mut decoder = CapsuleDecoder::default();
            for payload in [b"before".as_slice(), b"after".as_slice()] {
                if payload == b"after" {
                    assert!(handle.request_quiesce());
                    assert_eq!(goaway(&mut control).await, accepted_id + 4);
                    assert!(!task.0.is_finished());
                    assert_eq!(slots.available_permits(), 1);
                    // A standards-compliant client stops opening streams after
                    // GOAWAY. This sender has not consumed it, intentionally testing
                    // the server's required rejection of a racing request instead.
                    let mut rejected = sender.send_request(request(port)).await.unwrap();
                    assert!(matches!(
                        rejected.recv_response().await,
                        Err(StreamError::RemoteTerminate { code, .. })
                            if code == Code::H3_REQUEST_REJECTED
                    ));
                    assert_eq!(slots.available_permits(), 1);
                    let accepted = observation.stats().accepted_handshakes;
                    // With no server config Quinn 0.11.11/proto 0.11.17 handles
                    // unknown Initial packets through its stateless-reset path.
                    // That is not a promise of an immediate client-visible error:
                    // a new client cannot validate that reset token. Verify no
                    // handshake succeeds or is admitted, not an invented deadline
                    // for a transport refusal (RFC 9000 section 10.3).
                    let attempted = timeout(Duration::from_secs(1), async {
                        client.connect(address, "localhost").unwrap().await
                    })
                    .await;
                    assert!(!matches!(attempted, Ok(Ok(_))));
                    assert_eq!(observation.stats().accepted_handshakes, accepted);
                }
                tunnel
                    .send_data(encode_datagram_capsule(payload).unwrap())
                    .await
                    .unwrap();
                loop {
                    let mut data = tunnel
                        .recv_data()
                        .await
                        .unwrap()
                        .expect("old tunnel remains open");
                    let length = data.remaining();
                    let capsules = decoder.push(&data.copy_to_bytes(length)).unwrap();
                    if !capsules.is_empty() {
                        assert_eq!(capsules, vec![Bytes::from([b"\0", payload].concat())]);
                        break;
                    }
                }
            }
            (&mut echo.0).await.unwrap();
            tunnel.finish().await.unwrap();
            assert!(tunnel.recv_data().await.unwrap().is_none());
            assert!(connection.close_reason().is_none());
            assert!(
                !task.0.is_finished(),
                "idle H3 owner must not close pending transport work"
            );
            connection.close(0_u32.into(), b"maintenance test peer complete");
            (&mut task.0).await.unwrap().unwrap();
            client.wait_idle().await;
        })
        .await
        .expect("maintenance wire fixture stalled");
    }

    #[tokio::test]
    async fn delayed_capsule_reader_survives_quiesce_and_stopping_still_has_a_bounded_deadline() {
        timeout(Duration::from_secs(10), async {
            for stopping in [false, true] {
                let (endpoint, client) =
                    super::cancellation_tests::endpoints_with_send_window(64, None, Some(256));
                let server = server(endpoint);
                let address = server.endpoint.local_addr().unwrap();
                let handle = Handle::new();
                let mut task = AbortOnDrop(tokio::spawn(server.start(handle.clone())));
                let connection = client.connect(address, "localhost").unwrap().await.unwrap();
                let (_driver, mut sender) =
                    h3::client::new(h3_quinn::Connection::new(connection.clone()))
                        .await
                        .unwrap();
                let mut control = connection.accept_uni().await.unwrap();
                assert_eq!(varint(&mut control).await, 0);
                settings(&mut control).await;
                let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = udp.local_addr().unwrap().port();
                let expected = vec![0x5a; 1_024];
                let mut echo = AbortOnDrop(tokio::spawn({
                    let expected = expected.clone();
                    async move {
                        let mut bytes = [0; 32];
                        let (_, peer) = udp.recv_from(&mut bytes).await.unwrap();
                        udp.send_to(&expected, peer).await.unwrap();
                    }
                }));
                let mut tunnel = sender.send_request(request(port)).await.unwrap();
                assert_eq!(
                    tunnel.recv_response().await.unwrap().status(),
                    StatusCode::OK
                );
                // Observe GOAWAY before filling the small shared send queue: the
                // test must not itself starve the server's control-stream write.
                assert!(handle.request_quiesce());
                assert_eq!(goaway(&mut control).await, tunnel.id().into_inner() + 4);
                tunnel
                    .send_data(encode_datagram_capsule(b"request").unwrap())
                    .await
                    .unwrap();
                let mut first = tunnel
                    .recv_data()
                    .await
                    .unwrap()
                    .expect("first Capsule bytes");
                let first_length = first.remaining();
                assert!(
                    first_length < expected.len(),
                    "receive credit leaves the response pending"
                );
                let mut decoder = CapsuleDecoder::default();
                let mut capsules = decoder.push(&first.copy_to_bytes(first_length)).unwrap();
                assert!(
                    capsules.is_empty(),
                    "the reliable Capsule is still incomplete"
                );
                assert!(!task.0.is_finished());
                assert!(connection.close_reason().is_none());
                if stopping {
                    // No more receive credit: run_tunnel is inside send_data, not
                    // polling its stop branch. The listener must enforce the same
                    // real deadline and report abort, rather than false success.
                    handle.request_shutdown_at(Instant::now() + Duration::from_millis(20));
                    let error = (&mut task.0).await.unwrap().unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                } else {
                    tunnel.finish().await.unwrap();
                    while let Some(mut data) = tunnel.recv_data().await.unwrap() {
                        let length = data.remaining();
                        capsules.extend(decoder.push(&data.copy_to_bytes(length)).unwrap());
                    }
                    decoder.finish().unwrap();
                    assert_eq!(
                        capsules,
                        vec![Bytes::from([b"\0".as_slice(), &expected].concat())]
                    );
                    assert!(connection.close_reason().is_none());
                    assert!(!task.0.is_finished());
                }
                (&mut echo.0).await.unwrap();
                connection.close(0_u32.into(), b"capsule test peer complete");
                if !stopping {
                    (&mut task.0).await.unwrap().unwrap();
                }
                client.wait_idle().await;
            }
        })
        .await
        .expect("delayed Capsule fixture stalled");
    }
}

#[cfg(test)]
mod shutdown_tests {
    //! Shutdown completion is local ownership cleanup, never a delivery receipt.

    use std::{
        future::{pending, poll_fn},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct Dropped(Arc<AtomicUsize>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn endpoint_drain_reports_timeout_or_task_panic_after_reaping_connections() {
        timeout(Duration::from_secs(2), async {
            for panic in [false, true] {
                let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                let dropped = Arc::new(AtomicUsize::new(0));
                let (started, ready) = tokio::sync::oneshot::channel();
                let mut connections = JoinSet::new();
                connections.spawn({
                    let dropped = dropped.clone();
                    async move {
                        let _owned = Dropped(dropped);
                        let _ = started.send(());
                        if panic {
                            panic!("test-owned connection panic");
                        }
                        pending::<()>().await;
                    }
                });
                ready.await.unwrap();
                let handle = Handle::new();
                handle.request_shutdown_at(Instant::now() + Duration::from_millis(20));
                let error = drain_endpoint(&endpoint, &mut connections, &handle)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.kind(),
                    if panic {
                        io::ErrorKind::Other
                    } else {
                        io::ErrorKind::TimedOut
                    }
                );
                assert!(connections.is_empty());
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
            }
        })
        .await
        .expect("endpoint shutdown fixture stalled");
    }

    #[tokio::test]
    async fn connection_error_cleanup_joins_tunnels_and_datagram_before_returning() {
        timeout(Duration::from_secs(2), async {
            let dropped = Arc::new(AtomicUsize::new(0));
            let (tunnel_started, tunnel_ready) = tokio::sync::oneshot::channel();
            let mut tunnels = JoinSet::new();
            tunnels.spawn({
                let dropped = dropped.clone();
                async move {
                    let _owned = Dropped(dropped);
                    let _ = tunnel_started.send(());
                    pending::<Result<(), BoxError>>().await
                }
            });
            let (datagram_started, datagram_ready) = tokio::sync::oneshot::channel();
            let mut datagram = AbortOnDrop(tokio::spawn({
                let dropped = dropped.clone();
                async move {
                    let _owned = Dropped(dropped);
                    let _ = datagram_started.send(());
                    pending::<Result<(), BoxError>>().await
                }
            }));
            tunnel_ready.await.unwrap();
            datagram_ready.await.unwrap();

            reap_tunnels(&mut tunnels, false).await.unwrap();
            assert!(datagram.abort_and_join().await.unwrap_err().is_cancelled());
            assert!(tunnels.is_empty());
            assert_eq!(dropped.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("connection cleanup fixture stalled");
    }

    #[tokio::test]
    async fn ordinary_quic_peer_closure_does_not_fail_the_listener() {
        timeout(Duration::from_secs(10), async {
            let (endpoint, client) = super::cancellation_tests::endpoints(65_536, None);
            let handle = Handle::new();
            let server = MasqueServer {
                endpoint,
                auth: Arc::new(
                    crate::AuthMode {
                        username: None,
                        password: None,
                    }
                    .into(),
                ),
                connector: Arc::new(Connector::new(
                    None,
                    None,
                    None,
                    2,
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    None,
                )),
                tunnel_limit: Arc::new(Semaphore::new(2)),
                #[cfg(feature = "management")]
                leaf: None,
            };
            let address = server.endpoint.local_addr().unwrap();
            let mut task = AbortOnDrop(tokio::spawn(server.start(handle.clone())));
            // The second actual HTTP response proves a closed first peer did not
            // turn its connection-local error into a fatal listener result.
            for _ in 0..2 {
                let connection = client.connect(address, "localhost").unwrap().await.unwrap();
                let (mut driver, mut sender) =
                    h3::client::new(h3_quinn::Connection::new(connection.clone()))
                        .await
                        .unwrap();
                let mut driver = AbortOnDrop(tokio::spawn(async move {
                    poll_fn(|cx| driver.poll_close(cx)).await
                }));
                let mut stream = sender
                    .send_request(Request::get("https://localhost/").body(()).unwrap())
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                assert_eq!(
                    stream.recv_response().await.unwrap().status(),
                    StatusCode::BAD_REQUEST
                );
                drop(stream);
                drop(sender);
                connection.close(0_u32.into(), b"test peer complete");
                let _ = (&mut driver.0).await.unwrap();
            }
            handle.request_graceful_shutdown();
            (&mut task.0).await.unwrap().unwrap();
            client.wait_idle().await;
        })
        .await
        .expect("ordinary peer closure fixture stalled");
    }
}

#[cfg(all(test, feature = "management"))]
mod traffic_tests {
    //! Accounting assertions use actual RFC CONNECT-UDP requests and the production
    //! UDP/QUIC relay. They do not call a counter directly or replace the handler.
    use std::{future::poll_fn, net::SocketAddr, sync::Arc, time::Duration};

    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use bytes::{Buf, Bytes, BytesMut};
    use h3::{
        error::Code,
        ext::Protocol as H3Protocol,
        proto::{stream::StreamId, varint::VarInt},
    };
    use http::{Request, StatusCode};
    use quinn::{Connection, Endpoint};
    use tokio::{
        net::UdpSocket,
        task::{AbortHandle, JoinSet},
        time::timeout,
    };

    use super::{
        CapsuleDecoder, Connector, Handle, MAX_UDP_RELAY_PAYLOAD_SIZE, Semaphore, Source,
        encode_datagram_capsule,
    };
    use crate::{
        access::{self, Protocol, Reader},
        traffic::Snapshot,
    };

    type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
    type Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

    struct Fixture {
        server: Endpoint,
        client: Endpoint,
        connection: Connection,
        sender: Sender,
        reader: Reader,
        tasks: JoinSet<()>,
        server_task: AbortHandle,
    }

    impl Fixture {
        async fn new(users: usize, datagrams: bool, window: u32, mtu: Option<u16>) -> Self {
            let mut policy = access::tests::policy(1, 1);
            if users == 2 {
                let mut user = policy.users[0].clone();
                user.id = URL_SAFE_NO_PAD.encode([8; 16]);
                user.name = "Other managed MASQUE user".into();
                let mut credential = policy.credentials[0].clone();
                credential.id = URL_SAFE_NO_PAD.encode([9; 16]);
                credential.user_id = user.id.clone();
                credential.login = "vp2_09090909090909090909090909090909".into();
                credential.secret_digest =
                    access::digest_secret(&credential.id, &access::tests::secret());
                policy
                    .routing
                    .permissions
                    .push(access::routing::RoutePermission::legacy(user.id.clone()));
                policy
                    .presets
                    .users
                    .push(access::presets::UserPreset::native(user.id.clone()));
                policy.users.push(user);
                policy.credentials.push(credential);
            }
            let reader = Reader::new(policy).unwrap();
            let (server, client) = super::cancellation_tests::endpoints(window, mtu);
            let mut tasks = JoinSet::new();
            let connector = Connector::new(
                None,
                None,
                None,
                5,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                None,
            );
            let server_task = tasks.spawn({
                let server = server.clone();
                let reader = reader.clone();
                async move {
                    let _ = super::serve_incoming(
                        server.accept().await.unwrap(),
                        Arc::new(Source::Managed(reader)),
                        Arc::new(connector),
                        Arc::new(Semaphore::new(4)),
                        Handle::new(),
                    )
                    .await;
                }
            });
            let connection = client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut driver, sender) = h3::client::builder()
                .enable_datagram(datagrams)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            tasks.spawn(async move {
                let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            });
            Self {
                server,
                client,
                connection,
                sender,
                reader,
                tasks,
                server_task,
            }
        }

        async fn tunnel(&mut self, user: usize, target: SocketAddr) -> Stream {
            let authorization = authorization(user);
            let request = Request::connect(format!(
                "https://localhost/.well-known/masque/udp/127.0.0.1/{}/",
                target.port()
            ))
            .extension(H3Protocol::CONNECT_UDP)
            .header("capsule-protocol", "?1")
            .header("proxy-authorization", authorization)
            .body(())
            .unwrap();
            let mut stream = self.sender.send_request(request).await.unwrap();
            assert_eq!(
                stream.recv_response().await.unwrap().status(),
                StatusCode::OK
            );
            stream
        }

        fn value(&self, user: usize) -> Snapshot {
            let expected = if user == 0 {
                URL_SAFE_NO_PAD.encode([2; 16])
            } else {
                URL_SAFE_NO_PAD.encode([9; 16])
            };
            let expected_user = if user == 0 {
                URL_SAFE_NO_PAD.encode([1; 16])
            } else {
                URL_SAFE_NO_PAD.encode([8; 16])
            };
            let values = self.reader.traffic_registry().snapshot().unwrap();
            for value in &values {
                if value.protocol != Protocol::Masque {
                    assert_eq!(
                        value.value,
                        Snapshot {
                            upload: 0,
                            download: 0,
                            saturated: false
                        }
                    );
                }
            }
            let value = values
                .iter()
                .find(|value| {
                    value.credential_id.as_ref() == expected && value.protocol == Protocol::Masque
                })
                .unwrap();
            assert_eq!(value.user_id.as_ref(), expected_user);
            value.value
        }

        async fn released(&self, user: usize) {
            loop {
                match self.reader.authenticate(
                    login(user),
                    &access::tests::secret(),
                    Protocol::Masque,
                ) {
                    Ok(admission) => {
                        drop(admission);
                        return;
                    }
                    Err(access::Error::Capacity) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected managed fixture admission: {error:?}"),
                }
            }
        }

        async fn close(&mut self) {
            self.connection
                .close(0_u32.into(), b"managed traffic test complete");
            self.server
                .close(0_u32.into(), b"managed traffic test complete");
            self.client
                .close(0_u32.into(), b"managed traffic test complete");
            self.tasks.shutdown().await;
            self.server.wait_idle().await;
            self.client.wait_idle().await;
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.connection
                .close(0_u32.into(), b"owned fixture dropped");
            self.server.close(0_u32.into(), b"owned fixture dropped");
            self.client.close(0_u32.into(), b"owned fixture dropped");
            self.tasks.abort_all();
        }
    }

    fn login(user: usize) -> &'static str {
        if user == 0 {
            access::tests::LOGIN
        } else {
            "vp2_09090909090909090909090909090909"
        }
    }

    fn authorization(user: usize) -> String {
        format!(
            "Basic {}",
            STANDARD.encode([login(user).as_bytes(), b":", &access::tests::secret()].concat())
        )
    }

    fn capsule(context: u64, payload: &[u8]) -> Bytes {
        let context = VarInt::from_u64(context).unwrap();
        let length =
            VarInt::from_u64(u64::try_from(context.size() + payload.len()).unwrap()).unwrap();
        let mut bytes = BytesMut::new();
        VarInt::from_u64(0).unwrap().encode(&mut bytes);
        length.encode(&mut bytes);
        context.encode(&mut bytes);
        bytes.extend_from_slice(payload);
        bytes.freeze()
    }

    fn datagram(stream: StreamId, context: u64, payload: &[u8]) -> Bytes {
        let mut bytes = BytesMut::new();
        VarInt::from_u64(stream.index()).unwrap().encode(&mut bytes);
        VarInt::from_u64(context).unwrap().encode(&mut bytes);
        bytes.extend_from_slice(payload);
        bytes.freeze()
    }

    async fn received_capsule(stream: &mut Stream, expected: &[u8]) {
        let mut decoder = CapsuleDecoder::default();
        loop {
            let mut data = stream.recv_data().await.unwrap().unwrap();
            let remaining = data.remaining();
            let values = decoder.push(&data.copy_to_bytes(remaining)).unwrap();
            if !values.is_empty() {
                assert_eq!(values, vec![Bytes::from([b"\0", expected].concat())]);
                return;
            }
        }
    }

    #[tokio::test]
    async fn capsule_payload_excludes_metadata_and_silently_discarded_inputs() {
        timeout(Duration::from_secs(10), async {
            let mut fixture = Fixture::new(1, false, 16 * 1024, None).await;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = fixture.tunnel(0, udp.local_addr().unwrap()).await;
            assert_eq!(
                fixture.value(0),
                Snapshot {
                    upload: 0,
                    download: 0,
                    saturated: false
                }
            );
            // RFC9297 sections3.2/5.4 reserve 0x17 for ignored GREASE Capsules.
            // https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
            // Unknown contexts and path-size drops are not forwarded UDP payload.
            // https://www.rfc-editor.org/rfc/rfc9298.html#section-5
            // The ordered valid Capsule is our processing barrier.
            stream
                .send_data(Bytes::from_static(b"\x17\x03abc"))
                .await
                .unwrap();
            stream
                .send_data(capsule(2, b"unknown context"))
                .await
                .unwrap();
            stream
                .send_data(capsule(0, &vec![0x55; MAX_UDP_RELAY_PAYLOAD_SIZE + 1]))
                .await
                .unwrap();
            let upload = vec![0x61; 67];
            stream
                .send_data(encode_datagram_capsule(&upload).unwrap())
                .await
                .unwrap();
            let mut buffer = [0; 2048];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], upload);
            udp.send_to(&vec![0x66; MAX_UDP_RELAY_PAYLOAD_SIZE + 1], peer)
                .await
                .unwrap();
            let download = vec![0x62; 89];
            udp.send_to(&download, peer).await.unwrap();
            received_capsule(&mut stream, &download).await;
            assert_eq!(
                fixture.value(0),
                Snapshot {
                    upload: 67,
                    download: 89,
                    saturated: false
                }
            );
            stream.finish().await.unwrap();
            fixture.released(0).await;
            assert_eq!(
                fixture.value(0),
                Snapshot {
                    upload: 67,
                    download: 89,
                    saturated: false
                }
            );
            fixture.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn datagrams_on_one_quic_connection_keep_two_managed_identities_separate() {
        timeout(Duration::from_secs(10), async {
            // A fixed 2KiB loopback QUIC MTU lets an actual inbound Datagram exceed
            // the proxy UDP ceiling; merely failing client send would prove less.
            let mut fixture = Fixture::new(2, true, 16 * 1024, Some(2048)).await;
            assert!(
                fixture.connection.max_datagram_size().unwrap() > MAX_UDP_RELAY_PAYLOAD_SIZE + 8
            );
            let udp_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut a = fixture.tunnel(0, udp_a.local_addr().unwrap()).await;
            let mut b = fixture.tunnel(1, udp_b.local_addr().unwrap()).await;
            fixture
                .connection
                .send_datagram(datagram(a.id(), 2, b"unknown context"))
                .unwrap();
            fixture
                .connection
                .send_datagram(datagram(
                    a.id(),
                    0,
                    &vec![0x55; MAX_UDP_RELAY_PAYLOAD_SIZE + 1],
                ))
                .unwrap();
            let (upload_a, upload_b) = (vec![0x61; 23], vec![0x62; 47]);
            fixture
                .connection
                .send_datagram(datagram(a.id(), 0, &upload_a))
                .unwrap();
            fixture
                .connection
                .send_datagram(datagram(b.id(), 0, &upload_b))
                .unwrap();
            let mut buffer = [0; 2048];
            let (length, peer_a) = udp_a.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], upload_a);
            let (length, peer_b) = udp_b.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], upload_b);
            let (download_a, download_b) = (vec![0x63; 31], vec![0x64; 59]);
            udp_a
                .send_to(&vec![0x55; MAX_UDP_RELAY_PAYLOAD_SIZE + 1], peer_a)
                .await
                .unwrap();
            udp_a.send_to(&download_a, peer_a).await.unwrap();
            udp_b.send_to(&download_b, peer_b).await.unwrap();
            let mut seen = [false; 2];
            for _ in 0..2 {
                let value = fixture.connection.read_datagram().await.unwrap();
                let value = h3_datagram::datagram::Datagram::decode(value).unwrap();
                let (context, payload) = super::decode_varint(value.payload()).unwrap();
                assert_eq!(context, 0);
                if value.stream_id() == a.id() {
                    assert_eq!(payload, download_a);
                    seen[0] = true;
                } else {
                    assert_eq!(value.stream_id(), b.id());
                    assert_eq!(payload, download_b);
                    seen[1] = true;
                }
            }
            assert_eq!(seen, [true; 2]);
            assert_eq!(
                fixture.value(0),
                Snapshot {
                    upload: 23,
                    download: 31,
                    saturated: false
                }
            );
            assert_eq!(
                fixture.value(1),
                Snapshot {
                    upload: 47,
                    download: 59,
                    saturated: false
                }
            );
            a.finish().await.unwrap();
            b.finish().await.unwrap();
            fixture.released(0).await;
            fixture.released(1).await;
            fixture.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn negotiated_quic_datagram_size_drop_does_not_add_download() {
        timeout(Duration::from_secs(10), async {
            let mut fixture = Fixture::new(1, true, 16 * 1024, Some(1200)).await;
            assert!(fixture.connection.max_datagram_size().unwrap() < MAX_UDP_RELAY_PAYLOAD_SIZE);
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = fixture.tunnel(0, udp.local_addr().unwrap()).await;
            fixture
                .connection
                .send_datagram(datagram(stream.id(), 0, b"target address"))
                .unwrap();
            let mut buffer = [0; 64];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"target address");
            // Valid at the proxy's UDP ceiling but too large for this QUIC path:
            // the existing implementation drops, rather than Capsule-falling back.
            udp.send_to(&vec![0x55; MAX_UDP_RELAY_PAYLOAD_SIZE], peer)
                .await
                .unwrap();
            udp.send_to(b"small answer", peer).await.unwrap();
            let received = fixture.connection.read_datagram().await.unwrap();
            let received = h3_datagram::datagram::Datagram::decode(received).unwrap();
            assert_eq!(received.stream_id(), stream.id());
            assert_eq!(received.payload().as_ref(), b"\0small answer");
            assert_eq!(
                fixture.value(0),
                Snapshot {
                    upload: 14,
                    download: 12,
                    saturated: false
                }
            );
            stream.finish().await.unwrap();
            fixture.released(0).await;
            fixture.close().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stop_sending_retains_only_the_accepted_capsule_payload_prefix() {
        partial_capsule_retained(false).await;
    }

    #[tokio::test]
    async fn cancelling_the_real_server_retains_its_accepted_capsule_payload_prefix() {
        partial_capsule_retained(true).await;
    }

    async fn partial_capsule_retained(cancel_server: bool) {
        timeout(Duration::from_secs(10), async {
            let mut fixture = Fixture::new(1, false, 128, None).await;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = fixture.tunnel(0, udp.local_addr().unwrap()).await;
            stream
                .send_data(encode_datagram_capsule(b"request").unwrap())
                .await
                .unwrap();
            let mut buffer = [0; 64];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"request");
            udp.send_to(&vec![0x71; MAX_UDP_RELAY_PAYLOAD_SIZE], peer)
                .await
                .unwrap();
            let prefix = loop {
                let value = fixture.value(0);
                if value.download != 0 {
                    break value;
                }
                tokio::task::yield_now().await;
            };
            // Do not read DATA: the real QUIC stream window is the deterministic
            // barrier keeping send_data pending after a nonempty accepted prefix.
            assert_eq!(prefix.upload, 7);
            assert!(prefix.download < MAX_UDP_RELAY_PAYLOAD_SIZE as u64);
            if cancel_server {
                let server_id = fixture.server_task.id();
                fixture.server_task.abort();
                loop {
                    match fixture.tasks.join_next_with_id().await.unwrap() {
                        Err(error) if error.id() == server_id => {
                            assert!(error.is_cancelled());
                            break;
                        }
                        Ok((id, ())) => {
                            assert_ne!(id, server_id, "server finished before cancellation")
                        }
                        Err(error) => panic!("unexpected H3 driver task failure: {error}"),
                    }
                }
            } else {
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            }
            fixture.released(0).await;
            let retained = fixture.value(0);
            assert_eq!(retained.upload, 7);
            assert!(
                retained.download >= prefix.download
                    && retained.download < MAX_UDP_RELAY_PAYLOAD_SIZE as u64
            );
            if !cancel_server {
                let mut probe = fixture
                    .sender
                    .send_request(
                        Request::get("https://localhost/probe")
                            .header("proxy-authorization", authorization(0))
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    probe.recv_response().await.unwrap().status(),
                    StatusCode::BAD_REQUEST
                );
                probe.finish().await.unwrap();
                assert_eq!(fixture.value(0), retained);
            }
            fixture.close().await;
            assert_eq!(fixture.value(0), retained);
        })
        .await
        .unwrap();
    }
}
