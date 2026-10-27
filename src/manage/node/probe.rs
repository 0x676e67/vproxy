//! A one-shot identity probe: ordinary TLS verification and local registration
//! both finish before any HTTP request is sent. There are no redirects or TOFU.

use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, ProtocolVersion};
use rustls_pki_types::ServerName;
use serde::Deserialize;
use tokio::{net::TcpStream, task::JoinSet, time::timeout};
use tokio_rustls::TlsConnector;

use super::super::{store, tls};
use super::{CAPABILITIES, IDENTITY_PATH, PROTOCOL_VERSION, PublicOrigin};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Probe one explicitly registered peer over a canonical HTTPS origin. Node
/// private keys are file inputs, never command-line secrets or browser cookies.
#[derive(clap::Args)]
pub struct ProbeArgs {
    /// Canonical HTTPS origin, without a path, query, fragment or trailing slash
    #[arg(long)]
    pub(super) endpoint: String,
    /// Expected stable peer ID already bound to its actual leaf DER locally
    #[arg(long)]
    pub(super) peer_id: String,
    /// Explicit PEM CA roots for the node trust domain
    #[arg(long)]
    pub(super) ca: PathBuf,
    /// Local dual-purpose node leaf/chain PEM
    #[arg(long)]
    pub(super) cert: PathBuf,
    /// Private PEM key matching the local node leaf
    #[arg(long)]
    pub(super) key: PathBuf,
    /// Existing persistent management directory, explicitly migrated to schema 2
    #[arg(long)]
    pub(super) data_dir: Option<PathBuf>,
}

/// Owned counterpart of the server's fixed identity wire contract. Unexpected
/// fields are not accepted as new capabilities or implicit authorization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    protocol_version: u8,
    node_id: String,
    name: String,
    version: String,
    os: String,
    arch: String,
    capabilities: Vec<String>,
    verified_peer: PeerView,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerView {
    node_id: String,
    authorization_revision: u64,
}

struct PreparedProbe {
    directory: PathBuf,
    origin: PublicOrigin,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    expected_peer: String,
    local_id: String,
    recovery_key: Option<[u8; 32]>,
    loaded_key: [u8; 32],
    tls: Arc<ClientConfig>,
}

struct ProbeResult {
    identity: Identity,
    local_authorization_revision: u64,
}

/// Perform bounded synchronous startup, then a ten-second network/DB/HTTP probe.
///
/// Missing/old state, invalid TLS files, failed trust/name/DER bindings, rejected
/// HTTP, malformed or oversized replies and deadlines return errors. No remote
/// JSON field can grant permissions; it is only checked against prior local facts.
/// This read-only CLI does not take the process-author lock: normal probes must
/// remain usable while serve runs. Recovery/identity state is checked before TLS
/// loading and again before connecting; this is not a hostile same-UID filesystem
/// replacement defense or a reservation of mutable offline state.
pub(in crate::manage) fn probe(args: ProbeArgs) -> io::Result<()> {
    let prepared = prepare(args)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let result = runtime.block_on(async { timeout(PROBE_TIMEOUT, probe_once(prepared)).await });
    runtime.shutdown_timeout(Duration::from_secs(5));
    let result = result
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "node identity probe timed out"))??;
    let mut output = io::stdout().lock();
    writeln!(output, "peer_node_id={}", result.identity.node_id)?;
    writeln!(output, "peer_name={}", result.identity.name)?;
    writeln!(
        output,
        "local_node_id={}",
        result.identity.verified_peer.node_id
    )?;
    writeln!(
        output,
        "protocol_version={}",
        result.identity.protocol_version
    )?;
    writeln!(
        output,
        "local_authorization_revision={}",
        result.local_authorization_revision
    )?;
    writeln!(
        output,
        "remote_authorization_revision={}",
        result.identity.verified_peer.authorization_revision
    )
}

fn prepare(args: ProbeArgs) -> io::Result<PreparedProbe> {
    if !valid_id(&args.peer_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid expected node identity",
        ));
    }
    let origin = PublicOrigin::parse(&args.endpoint)?;
    let url =
        url::Url::parse(origin.value()).map_err(|_| invalid("invalid node probe endpoint"))?;
    let (host, server_name) = match url.host() {
        Some(url::Host::Domain(host)) => (
            host.to_owned(),
            ServerName::try_from(host.to_owned())
                .map_err(|_| invalid("invalid node probe hostname"))?,
        ),
        Some(url::Host::Ipv4(address)) => {
            (address.to_string(), ServerName::IpAddress(address.into()))
        }
        Some(url::Host::Ipv6(address)) => {
            (address.to_string(), ServerName::IpAddress(address.into()))
        }
        None => return Err(invalid("node probe endpoint has no host")),
    };
    let directory = super::super::directory(args.data_dir)?;
    let overview = store::inspect(&directory)?;
    if overview.schema_version < 2 {
        return Err(invalid(
            "node identity probe requires an explicit management schema migration",
        ));
    }
    let recovery_key = store::recovery::startup(&directory)?;
    let identity = tls::node_identity(&args.ca, &args.cert, &args.key)?;
    let loaded_key = identity.key_sha256()?;
    if recovery_key.is_some_and(|expected| expected != loaded_key) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "node TLS identity does not match the recovered node key",
        ));
    }
    Ok(PreparedProbe {
        directory,
        origin,
        host,
        port: url
            .port_or_known_default()
            .ok_or_else(|| invalid("node probe endpoint has no port"))?,
        server_name,
        expected_peer: args.peer_id,
        local_id: overview.node_id,
        recovery_key,
        loaded_key,
        tls: identity.client_config()?,
    })
}

async fn probe_once(prepared: PreparedProbe) -> io::Result<ProbeResult> {
    let directory = prepared.directory.clone();
    let local_id = prepared.local_id.clone();
    let expected = prepared.recovery_key;
    let loaded = prepared.loaded_key;
    tokio::task::spawn_blocking(move || {
        let overview = store::inspect(&directory)?;
        let current = store::recovery::startup(&directory)?;
        if overview.node_id != local_id
            || current != expected
            || current.is_some_and(|pin| pin != loaded)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local node identity or recovery state changed before probe",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::other("node probe startup validation task failed"))??;
    let stream = TcpStream::connect((prepared.host.as_str(), prepared.port))
        .await
        .map_err(|error| io::Error::new(error.kind(), "cannot connect to node endpoint"))?;
    let stream = TlsConnector::from(prepared.tls)
        .connect(prepared.server_name, stream)
        .await
        .map_err(|error| io::Error::new(error.kind(), "node TLS handshake failed"))?;
    if stream.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..])
        || stream.get_ref().1.protocol_version() != Some(ProtocolVersion::TLSv1_3)
    {
        return Err(invalid("node TLS did not negotiate TLS 1.3 and HTTP/1.1"));
    }
    let leaf = tls::checked_leaf(stream.get_ref().1.peer_certificates())?;
    let directory = prepared.directory;
    let expected = prepared.expected_peer.clone();
    let authorization = tokio::task::spawn_blocking(move || {
        let authorization = store::authorize_peer(&directory, &leaf)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "node TLS leaf is not registered",
            )
        })?;
        if authorization.node_id != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "node TLS leaf does not match the expected peer",
            ));
        }
        tls::verify_peer_name(&leaf, &authorization.expected_san)?;
        Ok::<_, io::Error>(authorization)
    })
    .await
    .map_err(|_| io::Error::other("node authorization task failed"))??;

    // Only now may application bytes leave this process. The peer's JSON ID
    // did not choose the endpoint, the trust root, or this authorization.
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(16 * 1024).max_headers(64);
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| io::Error::other("cannot initialize node HTTP connection"))?;
    let mut drivers = JoinSet::new();
    drivers.spawn(connection);
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(IDENTITY_PATH)
        .header(http::header::HOST, prepared.origin.authority())
        .header(http::header::ACCEPT, "application/json")
        .body(Empty::<Bytes>::new())
        .map_err(|_| invalid("cannot construct node identity request"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| io::Error::other("node identity request failed"))?;
    if response.status() != http::StatusCode::OK {
        let kind = if response.status() == http::StatusCode::FORBIDDEN {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::Other
        };
        return Err(io::Error::new(
            kind,
            format!(
                "node identity endpoint returned HTTP {}",
                response.status().as_u16()
            ),
        ));
    }
    let json_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !json_type {
        return Err(invalid("node identity endpoint did not return JSON"));
    }
    let mut body = response.into_body();
    let mut bytes = Vec::with_capacity(1024);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| io::Error::other("cannot read node identity response"))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let length = bytes
            .len()
            .checked_add(data.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or_else(|| invalid("node identity response exceeds its size limit"))?;
        bytes.reserve(length - bytes.len());
        bytes.extend_from_slice(&data);
    }
    let identity: Identity =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid node identity response"))?;
    validate_identity(&identity, &prepared.expected_peer, &prepared.local_id)?;
    drop(sender);
    // JoinSet owns the HTTP driver even on cancellation, timeout or parse error.
    drivers.shutdown().await;
    Ok(ProbeResult {
        identity,
        local_authorization_revision: authorization.authorization_revision,
    })
}

fn validate_identity(identity: &Identity, expected_peer: &str, local_id: &str) -> io::Result<()> {
    let text = |value: &str, maximum: usize| {
        !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
    };
    if identity.protocol_version != PROTOCOL_VERSION
        || identity.node_id != expected_peer
        || identity.verified_peer.node_id != local_id
        || !valid_id(&identity.node_id)
        || !valid_id(&identity.verified_peer.node_id)
        || !text(&identity.name, 128)
        || identity.name.trim() != identity.name
        || !text(&identity.version, 128)
        || !text(&identity.os, 64)
        || !text(&identity.arch, 64)
        || identity.verified_peer.authorization_revision == 0
        || identity.verified_peer.authorization_revision > i64::MAX as u64
        || identity.capabilities.len() != CAPABILITIES.len()
        || !identity
            .capabilities
            .iter()
            .zip(CAPABILITIES)
            .all(|(actual, expected)| actual == expected)
    {
        return Err(invalid(
            "node identity response does not match the verified protocol and identities",
        ));
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    let mut decoded = [0; 16];
    value.len() == 22 && matches!(URL_SAFE_NO_PAD.decode_slice(value, &mut decoded), Ok(16))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::node::tests::Fixture;

    fn args(fixture: &Fixture) -> ProbeArgs {
        ProbeArgs {
            endpoint: "https://localhost:9".into(),
            peer_id: fixture.server_id.clone(),
            ca: fixture.ca.clone(),
            cert: fixture.client_cert.clone(),
            key: fixture.client_key.clone(),
            data_dir: Some(fixture.client_state.clone()),
        }
    }

    fn restored(fixture: &Fixture, phase: &str, key: [u8; 32]) -> io::Result<()> {
        let connection =
            rusqlite::Connection::open(fixture.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
        connection.execute(
            "UPDATE recovery_state SET kind='restored',phase=?1,recovery_id=?2,source_node_id=?3,
             source_schema_version=13,source_database_sha256=?4,node_key_sha256=?5,
             imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
            rusqlite::params![phase, "AAAAAAAAAAAAAAAAAAAAAA", fixture.server_id, "3".repeat(64), &key[..]],
        ).map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn preparation_works_while_author_is_held_but_rejects_pending_or_wrong_key() -> io::Result<()> {
        let fixture = Fixture::new(true, true)?;
        let _author = store::lock(&fixture.client_state)?;
        assert!(prepare(args(&fixture)).is_ok());
        let key = tls::node_key_sha256(&fixture.client_key)?;
        restored(&fixture, "pending_review", key)?;
        assert_eq!(
            prepare(args(&fixture)).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        // Any other pin is rejected even if the supplied certificate/key pair
        // has valid CA, dual EKU and a matching private key of its own.
        let mut wrong = key;
        wrong[0] ^= 1;
        restored(&fixture, "ready", wrong)?;
        assert_eq!(
            prepare(args(&fixture)).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        restored(&fixture, "ready", key)?;
        assert!(prepare(args(&fixture)).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn prepared_probe_rechecks_local_recovery_before_any_connect() -> io::Result<()> {
        let fixture = tokio::task::spawn_blocking(|| Fixture::new(true, true))
            .await
            .map_err(io::Error::other)??;
        let prepared = prepare(args(&fixture))?;
        restored(
            &fixture,
            "pending_review",
            tls::node_key_sha256(&fixture.client_key)?,
        )?;
        let error = timeout(PROBE_TIMEOUT, probe_once(prepared))
            .await
            .map_err(io::Error::other)?
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "management recovery is pending; inspect its phase before selecting a recovery workflow"
        );
        Ok(())
    }
}
