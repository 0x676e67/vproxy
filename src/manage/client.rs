//! A single explicit HTTPS request, without redirects, proxies or background tasks.
//!
//! Bearer secrets are sent only after normal CA/SAN verification, TLS 1.3 and
//! HTTP/1.1 negotiation. RFC 6750 sections 2.1 and 5.2 require protecting the
//! credential in transport: <https://www.rfc-editor.org/rfc/rfc6750.html#section-5.2>.

use bytes::Bytes;
use futures_util::FutureExt as _;
use http::{StatusCode, header as http_header};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::ProtocolVersion;
use serde::Deserialize;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

mod header;

use super::{api::PublicOrigin, tls};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::{io, path::PathBuf, sync::Arc, time::Duration};

const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Explicit HTTPS destination and CA; the Authorization value stays in a private file.
#[derive(clap::Args)]
pub(super) struct ConnectionArgs {
    /// Canonical HTTPS management origin, without a trailing slash or path
    #[arg(long)]
    pub(super) origin: String,
    /// Explicit PEM CA bundle; no system trust or insecure fallback
    #[arg(long)]
    pub(super) ca: PathBuf,
    /// Private header file written by manage automation create or rotate
    #[arg(long)]
    pub(super) header_file: PathBuf,
}

/// Prepared only after validating all of the command's non-secret input.
pub(super) struct Connection {
    origin: PublicOrigin,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    authorization: header::Authorization,
}

impl Connection {
    /// Validate the origin before loading CA material or the private header.
    /// No socket opens until all synchronous input checks have succeeded.
    pub(super) fn prepare(args: ConnectionArgs) -> io::Result<Self> {
        let origin = PublicOrigin::parse(&args.origin)?;
        let url = url::Url::parse(origin.value()).map_err(|_| input("invalid query origin"))?;
        let (host, server_name) = match url.host() {
            Some(url::Host::Domain(host)) => (
                host.to_owned(),
                ServerName::try_from(host.to_owned())
                    .map_err(|_| input("invalid query hostname"))?,
            ),
            Some(url::Host::Ipv4(ip)) => (ip.to_string(), ServerName::IpAddress(ip.into())),
            Some(url::Host::Ipv6(ip)) => (ip.to_string(), ServerName::IpAddress(ip.into())),
            None => return Err(input("query origin has no host")),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| input("query origin has no port"))?;
        let tls = tls::admin_client_config(&args.ca)?;
        let authorization = header::Authorization::read(&args.header_file)?;
        Ok(Self {
            origin,
            host,
            port,
            server_name,
            tls,
            authorization,
        })
    }
}

/// Internal fixed requests. No command exposes an arbitrary HTTP method/path.
pub(super) enum Request {
    Get(String),
    Reserve(Vec<u8>),
    Execute { id: String, json: Vec<u8> },
}

impl Request {
    fn parts(self) -> (http::Method, String, Vec<u8>, StatusCode, &'static str) {
        match self {
            Self::Get(path) => (
                http::Method::GET,
                path,
                Vec::new(),
                StatusCode::OK,
                "management query",
            ),
            Self::Reserve(json) => (
                http::Method::POST,
                "/api/v1/proxy/user-operations".into(),
                json,
                StatusCode::CREATED,
                "management operation",
            ),
            Self::Execute { id, json } => (
                http::Method::POST,
                format!("/api/v1/proxy/user-operations/{id}/execute"),
                json,
                StatusCode::OK,
                "management operation",
            ),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Get(_) => "management query",
            Self::Reserve(_) | Self::Execute { .. } => "management operation",
        }
    }
}

/// Only locally chosen stage labels survive transport errors. HTTP libraries
/// and peers may put arbitrary header/body values in their own error messages.
fn transport(error: io::Error, label: &'static str, stage: &'static str) -> io::Error {
    io::Error::new(error.kind(), format!("{label} failed ({stage})"))
}

/// All DNS/connect/TLS/HTTP/body waits share one budget. Dropping this future
/// drops both the exchange and its driver; it never detaches a spawned task.
pub(super) async fn request(
    connection: Connection,
    request: Request,
    budget: Duration,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let label = request.label();
    timeout(budget, once(connection, request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{label} timed out")))?
}

async fn once(connection: Connection, request: Request) -> io::Result<Zeroizing<Vec<u8>>> {
    let Connection {
        origin,
        host,
        port,
        server_name,
        tls,
        authorization,
    } = connection;
    let (method, path, json, expected_status, label) = request.parts();
    let post = method == http::Method::POST;
    // Direct transport deliberately does not consult HTTP(S)_PROXY or NO_PROXY.
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| transport(error, label, "connect"))?;
    let stream = TlsConnector::from(tls)
        .connect(server_name, stream)
        .await
        .map_err(|error| transport(error, label, "tls"))?;
    if stream.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..])
        || stream.get_ref().1.protocol_version() != Some(ProtocolVersion::TLSv1_3)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "management TLS negotiation is unsupported",
        ));
    }
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(16 * 1024).max_headers(64);
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| transport(io::Error::other(error), label, "http"))?;
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header(http_header::HOST, origin.authority())
        .header(http_header::ACCEPT, "application/json")
        .header(http_header::AUTHORIZATION, authorization.into_value());
    if post {
        request = request.header(http_header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(Full::new(Bytes::from(json)))
        .map_err(|_| input("cannot construct management query"))?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| transport(io::Error::other(error), label, "http"))?;
        let status = response.status();
        // This is a one-origin credential. Never follow Location, even to HTTPS.
        // RFC 9110 section 15.4 leaves automatic redirection a client decision:
        // <https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4>.
        if status.is_redirection() {
            let code = if matches!(status.as_u16(), 300 | 301 | 302 | 303 | 305 | 307 | 308) {
                "redirect_refused"
            } else {
                // 304 is a conditional-cache result, not a redirect. This CLI
                // sends no conditional request and accepts neither response.
                "request_rejected"
            };
            return Err(rejection(status, code, label));
        }
        let mut types = response.headers().get_all(http_header::CONTENT_TYPE).iter();
        let json = types
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if !json
            || types.next().is_some()
            || response
                .headers()
                .contains_key(http_header::CONTENT_ENCODING)
        {
            return Err(if status == expected_status {
                response_error()
            } else {
                rejection(status, "request_rejected", label)
            });
        }
        let mut body = response.into_body();
        // Keep arbitrary response bytes in one zeroizing bounded owner. Only a
        // typed, validated public response may be re-encoded to stdout afterwards.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| transport(io::Error::other(error), label, "body"))?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            bytes
                .len()
                .checked_add(data.len())
                .filter(|length| *length <= MAX_RESPONSE_BYTES)
                .ok_or_else(response_error)?;
            bytes.extend_from_slice(&data);
        }
        if status != expected_status {
            return Err(rejection(status, rejection_code(status, &bytes), label));
        }
        Ok(bytes)
    };
    tokio::pin!(exchange, connection);
    tokio::select! {
        biased;
        result = &mut exchange => result,
        result = &mut connection => {
            // A clean Connection: close may finish the driver after placing the
            // complete response in its channel. Consume that buffered response;
            // do not call it a protocol error or wait for keepalive EOF.
            match result {
                Ok(()) => exchange.await,
                Err(error) => {
                    // Hyper can retain a complete framed response even if the
                    // connection later fails. Preserve a buffered final result;
                    // otherwise report this driver failure without waiting for
                    // the outer deadline. A Pending exchange is dropped here.
                    exchange.as_mut().now_or_never().unwrap_or_else(|| {
                        Err(transport(io::Error::other(error), label, "http"))
                    })
                }
            }
        }
    }
}

/// Borrow the code from the bounded body instead of copying arbitrary remote
/// strings into diagnostics. Even a recognized code must match its HTTP status.
fn rejection_code(status: StatusCode, bytes: &[u8]) -> &'static str {
    #[derive(Deserialize)]
    struct ErrorBody<'a> {
        #[serde(borrow)]
        error: ErrorDetail<'a>,
    }
    #[derive(Deserialize)]
    struct ErrorDetail<'a> {
        code: &'a str,
    }
    let code = serde_json::from_slice::<ErrorBody<'_>>(bytes)
        .ok()
        .map(|body| body.error.code);
    match (status.as_u16(), code) {
        (400, Some("invalid_pagination")) => "invalid_pagination",
        (400, Some("invalid_user_search")) => "invalid_user_search",
        (400, Some("invalid_user_search_cursor")) => "invalid_user_search_cursor",
        (400, Some("invalid_automation_authentication")) => "invalid_automation_authentication",
        (400, Some("invalid_query")) => "invalid_query",
        (400, Some("invalid_revision")) => "invalid_revision",
        (400, Some("invalid_resource_id")) => "invalid_resource_id",
        (400, Some("invalid_operation")) => "invalid_operation",
        (401, Some("authentication_required")) => "authentication_required",
        (401, Some("invalid_token")) => "invalid_token",
        (403, Some("automation_route_denied")) => "automation_route_denied",
        (403, Some("policy_denied")) => "policy_denied",
        (403, Some("insufficient_scope")) => "insufficient_scope",
        (403, Some("operation_denied")) => "operation_denied",
        (404, Some("resource_not_found")) => "resource_not_found",
        (404, Some("operation_not_queryable")) => "operation_not_queryable",
        (409, Some("user_search_changed")) => "user_search_changed",
        (409, Some("operation_conflict")) => "operation_conflict",
        (409, Some("operation_capacity")) => "operation_capacity",
        (429, _) => "rate_limited",
        (503, Some("policy_busy")) => "policy_busy",
        (503, Some("policy_unavailable")) => "policy_unavailable",
        (503, Some("management_upgrade_required")) => "management_upgrade_required",
        _ => "request_rejected",
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{label} rejected ({status}, {code})")]
struct Rejected {
    label: &'static str,
    status: u16,
    code: &'static str,
}

fn rejection(status: StatusCode, code: &'static str, label: &'static str) -> io::Error {
    let kind = match status.as_u16() {
        400 => io::ErrorKind::InvalidInput,
        401 | 403 => io::ErrorKind::PermissionDenied,
        404 => io::ErrorKind::NotFound,
        409 => io::ErrorKind::AlreadyExists,
        429 | 503 => io::ErrorKind::WouldBlock,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        Rejected {
            label,
            status: status.as_u16(),
            code,
        },
    )
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn response_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent management query response",
    )
}
