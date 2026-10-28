//! Bounded, unauthenticated release reads. URLs and response text never become
//! diagnostics: GitHub asset redirects can contain short-lived signed queries.

use std::{
    fs::File,
    io::{self, Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{StatusCode, Url, blocking::Response, header};
use self_update::update::{Release, ReleaseAsset};
use sha2::{Digest, Sha256};

const TOTAL: Duration = Duration::from_secs(120);
const CONNECT: Duration = Duration::from_secs(10);
const MAX_METADATA: usize = 4 * 1024 * 1024;
const MAX_CHECKSUM: usize = 512;
const MAX_ARCHIVE: u64 = 128 * 1024 * 1024;
const API: &str = "https://api.github.com/repos/0x676e67/vproxy/releases";
const ASSET_PATH: &str = "/0x676e67/vproxy/releases/download/";
const REDIRECT_HOSTS: [&str; 3] = [
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];

/// One explicit update attempt shares this deadline across metadata, checksum,
/// redirects and archive reads. Blocking DNS teardown and filesystem calls are
/// not hard-interruptible; the caller checks the budget again before replacing.
pub(super) struct Client {
    http: reqwest::blocking::Client,
    deadline: Instant,
    #[cfg(test)]
    origin: Option<Url>,
}

impl Client {
    pub(super) fn new() -> io::Result<Self> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::build(roots, TOTAL, false)
    }

    fn build(roots: rustls::RootCertStore, budget: Duration, no_proxy: bool) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| invalid("invalid update time budget"))?;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("cannot configure update TLS"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Configure the async client's total body deadline as well as the
        // blocking wrapper timeout, which alone resets on each read. Do not set
        // async read_timeout: reqwest 0.12 constructs its per-read Tokio timer
        // while blocking::Response polls the body outside that runtime.
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .connect_timeout(CONNECT)
            .timeout(budget)
            .user_agent("vproxy-self-update");
        // Production deliberately retains reqwest's environment proxy support.
        // Only private loopback fixtures disable proxies.
        if no_proxy {
            builder = builder.no_proxy();
        }
        let http = reqwest::blocking::ClientBuilder::from(builder)
            .timeout(budget)
            .build()
            .map_err(|_| io::Error::other("cannot create update HTTP client"))?;
        Ok(Self {
            http,
            deadline,
            #[cfg(test)]
            origin: None,
        })
    }

    pub(super) fn check_deadline(&self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "update time budget exhausted"))
    }

    /// Read the same first API page and retain its order and greater-version
    /// policy. Prereleases retain the existing selector's semantics. Drafts are
    /// never candidates. Release notes and arbitrary display names are dropped.
    pub(super) fn releases(&self, current: &str) -> io::Result<Vec<Release>> {
        self_update::version::bump_is_greater(current, current)
            .map_err(|_| invalid("invalid compiled update version"))?;
        let url = self.metadata_url()?;
        let response = self.get(url, "application/vnd.github+json")?;
        if response.status() != StatusCode::OK {
            return Err(invalid("update metadata request failed"));
        }
        let bytes = self.read_limited(response, MAX_METADATA)?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid update metadata"))?;
        let rows = json
            .as_array()
            .ok_or_else(|| invalid("invalid update metadata"))?;
        if rows.len() > 100 {
            return Err(invalid("too many update releases"));
        }
        let mut releases = Vec::new();
        for row in rows {
            if row.get("draft").and_then(serde_json::Value::as_bool) == Some(true) {
                continue;
            }
            let Some(tag) = row.get("tag_name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let version = tag.trim_start_matches('v');
            if !self_update::version::bump_is_greater(current, version).unwrap_or(false) {
                continue;
            }
            if !component(tag, 128) {
                return Err(invalid("invalid update release tag"));
            }
            // Keep an identifiable newer release even when its asset list is
            // absent or malformed. Selection must fail on that release rather
            // than silently installing an older version with available assets.
            let assets = row
                .get("assets")
                .and_then(serde_json::Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if assets.len() > 256 {
                return Err(invalid("too many update release assets"));
            }
            let mut parsed = Vec::new();
            for asset in assets {
                let Some(name) = asset.get("name").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if !component(name, 256) {
                    continue;
                }
                let expected = format!("{}{tag}/{name}", self.asset_prefix());
                // An unrelated legacy asset must not reject the entire list.
                // A selected malformed URL remains an exact named asset, but
                // cannot be fetched; it must not cause an older-version fallback.
                let download_url = match asset
                    .get("browser_download_url")
                    .and_then(serde_json::Value::as_str)
                {
                    Some(url) if url == expected => expected,
                    _ => String::new(),
                };
                parsed.push(ReleaseAsset {
                    name: name.to_owned(),
                    download_url,
                });
            }
            releases.push(Release {
                name: tag.to_owned(),
                version: version.to_owned(),
                date: String::new(),
                body: None,
                assets: parsed,
            });
        }
        self.check_deadline()?;
        Ok(releases)
    }

    /// Require the repository's exact single-line checksum format, including
    /// the archive basename; a digest for another package is not interchangeable.
    pub(super) fn read_checksum(&self, url: &str, archive_name: &str) -> io::Result<[u8; 32]> {
        if !component(archive_name, 256) || !archive_name.ends_with(".tar.gz") {
            return Err(invalid("invalid update archive name"));
        }
        let (url, name) = self.asset_url(url)?;
        if name != format!("{archive_name}.sha256") {
            return Err(invalid("update checksum does not match the archive name"));
        }
        let response = self.asset_response(url)?;
        let bytes = self.read_limited(response, MAX_CHECKSUM)?;
        parse_checksum(&bytes, archive_name)
    }

    /// Stream compressed bytes without content decoding, hash those same bytes,
    /// and leave any partial output solely in the caller's private staging file.
    pub(super) fn download(
        &self,
        url: &str,
        expected: [u8; 32],
        output: &mut File,
    ) -> io::Result<()> {
        let (url, name) = self.asset_url(url)?;
        if !name.starts_with("vproxy-") || !name.ends_with(".tar.gz") {
            return Err(invalid("invalid update archive URL"));
        }
        let mut response = self.asset_response(url)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARCHIVE)
        {
            return Err(invalid("update archive exceeds its byte limit"));
        }
        self.copy_verified(&mut response, output, expected, MAX_ARCHIVE)
    }

    fn copy_verified(
        &self,
        input: &mut impl Read,
        output: &mut impl Write,
        expected: [u8; 32],
        limit: u64,
    ) -> io::Result<()> {
        let mut hash = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            self.check_deadline()?;
            let read = input.read(&mut buffer).map_err(read_error)?;
            if read == 0 {
                break;
            }
            count = count
                .checked_add(read as u64)
                .filter(|count| *count <= limit)
                .ok_or_else(|| invalid("update archive exceeds its byte limit"))?;
            output
                .write_all(&buffer[..read])
                .map_err(|_| io::Error::other("cannot write private update download"))?;
            hash.update(&buffer[..read]);
        }
        self.check_deadline()?;
        if <[u8; 32]>::from(hash.finalize()) != expected {
            return Err(invalid("update archive checksum mismatch"));
        }
        Ok(())
    }

    fn get(&self, url: Url, accept: &'static str) -> io::Result<Response> {
        let response = self
            .http
            .get(url)
            .header(header::ACCEPT, accept)
            .header(header::ACCEPT_ENCODING, "identity")
            .timeout(self.remaining()?)
            .send()
            .map_err(|error| {
                io::Error::new(
                    if error.is_timeout() {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::Other
                    },
                    "update HTTP request failed",
                )
            })?;
        if response
            .headers()
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(invalid("encoded update response is not accepted"));
        }
        Ok(response)
    }

    fn asset_response(&self, mut url: Url) -> io::Result<Response> {
        for followed in 0..=5 {
            let response = self.get(url.clone(), "application/octet-stream")?;
            if response.status() == StatusCode::OK {
                return Ok(response);
            }
            if !matches!(
                response.status(),
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) || followed == 5
            {
                return Err(invalid(
                    "update asset request failed or exceeded its redirect limit",
                ));
            }
            let mut locations = response.headers().get_all(header::LOCATION).iter();
            let location = locations
                .next()
                .and_then(|value| value.to_str().ok())
                .filter(|location| location.len() <= 4096)
                .ok_or_else(|| invalid("invalid update asset redirect"))?;
            if locations.next().is_some() || has_userinfo(location) {
                return Err(invalid("invalid update asset redirect"));
            }
            let next = url
                .join(location)
                .map_err(|_| invalid("invalid update asset redirect"))?;
            self.check_redirect(&next)?;
            url = next;
        }
        Err(invalid("update asset redirect limit exceeded"))
    }

    fn read_limited(&self, mut response: Response, limit: usize) -> io::Result<Vec<u8>> {
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(invalid("update response exceeds its byte limit"));
        }
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            self.check_deadline()?;
            let read = response.read(&mut buffer).map_err(read_error)?;
            if read == 0 {
                break;
            }
            if bytes
                .len()
                .checked_add(read)
                .is_none_or(|length| length > limit)
            {
                return Err(invalid("update response exceeds its byte limit"));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        self.check_deadline()?;
        Ok(bytes)
    }

    fn metadata_url(&self) -> io::Result<Url> {
        #[cfg(test)]
        if let Some(origin) = &self.origin {
            return origin
                .join("/repos/0x676e67/vproxy/releases")
                .map_err(|_| invalid("invalid test update origin"));
        }
        Url::parse(API).map_err(|_| invalid("invalid compiled update metadata URL"))
    }

    fn asset_prefix(&self) -> String {
        #[cfg(test)]
        if let Some(origin) = &self.origin {
            return format!("{}{ASSET_PATH}", origin.origin().ascii_serialization());
        }
        format!("https://github.com{ASSET_PATH}")
    }

    fn asset_url(&self, input: &str) -> io::Result<(Url, String)> {
        if input.len() > 4096 || has_userinfo(input) {
            return Err(invalid("invalid update asset URL"));
        }
        let url = Url::parse(input).map_err(|_| invalid("invalid update asset URL"))?;
        let path = url
            .path()
            .strip_prefix(ASSET_PATH)
            .ok_or_else(|| invalid("invalid update asset URL"))?;
        let (tag, name) = path
            .split_once('/')
            .ok_or_else(|| invalid("invalid update asset URL"))?;
        if !component(tag, 128)
            || !component(name, 256)
            || input != format!("{}{tag}/{name}", self.asset_prefix())
        {
            return Err(invalid("invalid update asset URL"));
        }
        self.check_redirect(&url)?;
        let name = name.to_owned();
        Ok((url, name))
    }

    fn check_redirect(&self, url: &Url) -> io::Result<()> {
        let allowed = url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url
                .host_str()
                .is_some_and(|host| REDIRECT_HOSTS.contains(&host));
        #[cfg(test)]
        let allowed = self.origin.as_ref().map_or(allowed, |origin| {
            url.scheme() == "https" && url.origin() == origin.origin()
        });
        if !allowed
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid("invalid update asset redirect"));
        }
        Ok(())
    }
}

fn component(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn has_userinfo(input: &str) -> bool {
    input.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    }) || input.strip_prefix("//").is_some_and(|rest| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

fn parse_checksum(bytes: &[u8], name: &str) -> io::Result<[u8; 32]> {
    let suffix = format!("  {name}\n");
    let digest = bytes
        .strip_suffix(suffix.as_bytes())
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
        .ok_or_else(|| invalid("invalid update checksum file"))?;
    let mut decoded = [0_u8; 32];
    for (out, pair) in decoded.iter_mut().zip(digest.chunks_exact(2)) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| invalid("invalid update checksum file"))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| invalid("invalid update checksum file"))?;
        *out = (high * 16 + low) as u8;
    }
    Ok(decoded)
}

fn read_error(error: io::Error) -> io::Error {
    // blocking::Response wraps reqwest timeouts in io::ErrorKind::Other.
    // Preserve the timeout classification without retaining its URL/source.
    let timed_out = error.kind() == io::ErrorKind::TimedOut
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<reqwest::Error>())
            .is_some_and(reqwest::Error::is_timeout);
    io::Error::new(
        if timed_out {
            io::ErrorKind::TimedOut
        } else {
            error.kind()
        },
        "cannot read update response",
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
    };

    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use super::*;

    const NAME: &str = "vproxy-99.0.0-x86_64-unknown-linux-musl.tar.gz";
    const TAG: &str = "v99.0.0";

    /// The only configurable origin is compiled into tests. The leaf is trusted
    /// only by this fixture's client; no OS trust, DNS or environment is modified.
    struct Fixture {
        origin: Url,
        certificate: CertificateDer<'static>,
        stop: Arc<AtomicBool>,
        count: Arc<AtomicUsize>,
        body_started: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Fixture {
        fn new(handler: impl Fn(&str, &str) -> Vec<u8> + Send + 'static) -> Self {
            Self::with_body_delay(handler, None)
        }

        fn with_body_delay(
            handler: impl Fn(&str, &str) -> Vec<u8> + Send + 'static,
            delay: Option<Duration>,
        ) -> Self {
            let generated =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            let certificate = generated.cert.der().clone();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
            )
            .unwrap();
            let config = Arc::new(config);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let origin =
                Url::parse(&format!("https://{}/", listener.local_addr().unwrap())).unwrap();
            let base = origin.origin().ascii_serialization();
            let stop = Arc::new(AtomicBool::new(false));
            let count = Arc::new(AtomicUsize::new(0));
            let body_started = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let accepted = count.clone();
            let sent_body = body_started.clone();
            let worker = thread::spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // The listener is nonblocking only for bounded fixture
                            // shutdown. Windows accepted sockets can inherit that
                            // mode; StreamOwned needs blocking I/O here, or an early
                            // WouldBlock would discard a valid TLS handshake.
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                            let mut stream = rustls::StreamOwned::new(connection, stream);
                            let Some(path) = request_path(&mut stream) else {
                                continue;
                            };
                            accepted.fetch_add(1, Ordering::SeqCst);
                            let response = handler(&path, &base);
                            if let Some(delay) = delay {
                                let first = response
                                    .windows(4)
                                    .position(|bytes| bytes == b"\r\n\r\n")
                                    .unwrap()
                                    + 5;
                                if stream
                                    .write_all(&response[..first])
                                    .and_then(|()| stream.flush())
                                    .is_ok()
                                {
                                    sent_body.store(true, Ordering::SeqCst);
                                    thread::sleep(delay);
                                    let _ = stream
                                        .write_all(&response[first..])
                                        .and_then(|()| stream.flush());
                                }
                                continue;
                            }
                            // Negative TLS/deadline cases intentionally close early.
                            let _ = stream.write_all(&response).and_then(|()| stream.flush());
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("fixture accept failed: {error:?}"),
                    }
                }
            });
            Self {
                origin,
                certificate,
                stop,
                count,
                body_started,
                worker: Some(worker),
            }
        }

        fn client(&self, trust: bool, budget: Duration) -> Client {
            let mut roots = rustls::RootCertStore::empty();
            if trust {
                roots.add(self.certificate.clone()).unwrap();
            }
            let mut client = Client::build(roots, budget, true).unwrap();
            client.origin = Some(self.origin.clone());
            client
        }

        fn asset(&self, name: &str) -> String {
            format!(
                "{}{ASSET_PATH}{TAG}/{name}",
                self.origin.origin().ascii_serialization()
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    fn request_path(
        stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    ) -> Option<String> {
        let mut header = Vec::new();
        let mut byte = [0];
        while header.len() < 8192 && !header.ends_with(b"\r\n\r\n") {
            let read = match stream.read(&mut byte) {
                Ok(read) => read,
                Err(error) => {
                    eprintln!("update_loopback_server_read_failed kind={:?}", error.kind());
                    return None;
                }
            };
            if read != 1 {
                return None;
            }
            header.push(byte[0]);
        }
        let text = std::str::from_utf8(&header).ok()?;
        text.lines()
            .next()?
            .split_whitespace()
            .nth(1)
            .map(str::to_owned)
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        let mut result = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        result.extend_from_slice(body);
        result
    }

    fn redirect(location: &str) -> Vec<u8> {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
    }

    #[test]
    fn tls_metadata_checksum_and_archive_use_same_exact_tag_and_raw_bytes() {
        let payload = b"compressed asset bytes, not an executed program";
        let expected: [u8; 32] = Sha256::digest(payload).into();
        let digest = expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let fixture = Fixture::new(move |path, base| {
            if path == "/repos/0x676e67/vproxy/releases" {
                ok(serde_json::to_vec(&serde_json::json!([
                {"tag_name":"v99.0.0", "draft":false, "body":"do not print this release note",
                 "assets":[
                    {"name":NAME,"browser_download_url":format!("{base}{ASSET_PATH}{TAG}/{NAME}")},
                    {"name":format!("{NAME}.sha256"),"browser_download_url":format!("{base}{ASSET_PATH}{TAG}/{NAME}.sha256")},
                    {"name":"legacy.zip","browser_download_url":"http://unrelated.invalid/signed?secret=value"}
                 ]},
                {"tag_name":"v100.0.0", "draft":true,"assets":[]}
            ])).unwrap().as_slice())
            } else if path.ends_with(".sha256") {
                ok(format!("{digest}  {NAME}\n").as_bytes())
            } else {
                ok(payload)
            }
        });
        let client = fixture.client(true, Duration::from_secs(5));
        let releases = client.releases("1.0.0").unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "99.0.0");
        assert_eq!(releases[0].name, TAG);
        assert!(releases[0].body.is_none());
        assert_eq!(releases[0].assets[2].download_url, "");
        let checksum = client
            .read_checksum(&fixture.asset(&format!("{NAME}.sha256")), NAME)
            .unwrap();
        assert_eq!(checksum, expected);
        let mut stage = super::super::staging::Stage::new().unwrap();
        let mut output = stage.create("download.tar.gz").unwrap();
        client
            .download(&fixture.asset(NAME), checksum, &mut output)
            .unwrap();
        assert_eq!(output.metadata().unwrap().len(), payload.len() as u64);
        assert_eq!(fixture.count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn tls_requires_the_fixture_root_and_errors_hide_response_urls() {
        let fixture = Fixture::new(|_, _| ok(b"[]"));
        let client = fixture.client(false, Duration::from_secs(3));
        let error = client.releases("1.0.0").unwrap_err();
        assert_eq!(error.to_string(), "update HTTP request failed");
        assert!(!format!("{error:?}").contains("127.0.0.1"));
        assert_eq!(fixture.count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn newer_release_without_assets_is_not_removed_before_selection() {
        let fixture = Fixture::new(|_, base| {
            ok(serde_json::to_vec(&serde_json::json!([
        {"tag_name":"v100.0.0", "draft":false},
        {"tag_name":"v99.0.0", "draft":false, "assets":[
            {"name":NAME,"browser_download_url":format!("{base}{ASSET_PATH}{TAG}/{NAME}")},
            {"name":format!("{NAME}.sha256"),"browser_download_url":format!("{base}{ASSET_PATH}{TAG}/{NAME}.sha256")}
        ]}
    ])).unwrap().as_slice())
        });
        let client = fixture.client(true, Duration::from_secs(3));
        let releases = client.releases("99.0.0").unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "100.0.0");
        assert!(releases[0].assets.is_empty());
        let releases = client.releases("1.0.0").unwrap();
        assert_eq!(releases.len(), 2);
        let selected = super::super::select(releases, "1.0.0").unwrap().unwrap();
        assert_eq!(selected.version, "100.0.0");
        assert!(selected.assets.is_empty());
    }

    #[test]
    fn metadata_never_follows_redirects_and_assets_stop_after_five() {
        let fixture = Fixture::new(|path, base| redirect(&format!("{base}{path}")));
        let client = fixture.client(true, Duration::from_secs(5));
        assert!(client.releases("1.0.0").is_err());
        assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
        let mut stage = super::super::staging::Stage::new().unwrap();
        let mut output = stage.create("download.tar.gz").unwrap();
        let error = client
            .download(&fixture.asset(NAME), [0; 32], &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("redirect limit"));
        assert_eq!(fixture.count.load(Ordering::SeqCst), 7);
        assert_eq!(output.metadata().unwrap().len(), 0);
    }

    #[test]
    fn tls_redirect_cannot_downgrade_and_content_encoding_is_not_decoded() {
        for location in [
            "http://127.0.0.1/download?do-not-leak",
            "https://user:secret@github.com/hidden",
            "https://example.org/hidden",
        ] {
            let fixture = Fixture::new(move |_, _| redirect(location));
            let client = fixture.client(true, Duration::from_secs(3));
            let mut stage = super::super::staging::Stage::new().unwrap();
            let error = client
                .download(
                    &fixture.asset(NAME),
                    [0; 32],
                    &mut stage.create("download.tar.gz").unwrap(),
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "invalid update asset redirect");
            assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
        }
        let fixture = Fixture::new(|_, _| {
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        });
        let client = fixture.client(true, Duration::from_secs(3));
        assert_eq!(
            client.releases("1.0.0").unwrap_err().to_string(),
            "encoded update response is not accepted"
        );
    }

    #[test]
    fn actual_chunked_checksum_bytes_are_bounded_without_content_length() {
        let fixture = Fixture::new(|_, _| {
            let body = vec![b'a'; MAX_CHECKSUM + 1];
            let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
            response.extend(body);
            response.extend_from_slice(b"\r\n0\r\n\r\n");
            response
        });
        let client = fixture.client(true, Duration::from_secs(3));
        let error = client
            .read_checksum(&fixture.asset(&format!("{NAME}.sha256")), NAME)
            .unwrap_err();
        assert_eq!(error.to_string(), "update response exceeds its byte limit");
    }

    #[test]
    fn deadline_covers_the_whole_attempt_not_only_one_request() {
        let fixture = Fixture::new(|_, _| ok(b"[]"));
        let mut client = fixture.client(true, Duration::from_secs(3));
        assert!(client.releases("1.0.0").unwrap().is_empty());
        client.deadline = Instant::now();
        assert_eq!(
            client.releases("1.0.0").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            client.check_deadline().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn actual_tls_body_stall_expires_after_headers_and_first_body_byte() {
        let fixture = Fixture::with_body_delay(|_, _| ok(b"[]"), Some(Duration::from_millis(800)));
        let mut client = fixture.client(true, Duration::from_secs(3));
        client.deadline = Instant::now()
            .checked_add(Duration::from_millis(400))
            .unwrap();
        // Headers must have completed before asserting the body timeout. The
        // already-created request deadline remains active during blocking reads.
        let response = client
            .get(
                client.metadata_url().unwrap(),
                "application/vnd.github+json",
            )
            .unwrap();
        let error = client.read_limited(response, MAX_METADATA).unwrap_err();
        assert!(fixture.body_started.load(Ordering::SeqCst));
        assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "cannot read update response");
    }

    #[test]
    fn checksum_is_one_exact_record_and_payload_limit_is_checked_before_write() {
        let digest = "00".repeat(32);
        assert_eq!(
            parse_checksum(format!("{digest}  {NAME}\n").as_bytes(), NAME).unwrap(),
            [0; 32]
        );
        for invalid in [
            format!("{digest}  other.tar.gz\n"),
            format!("{digest}  {NAME}\nextra\n"),
            format!("{digest} *{NAME}\n"),
            format!("{}  {NAME}\n", "z".repeat(64)),
            format!("{}  {NAME}\n", "A".repeat(64)),
            format!("{digest}  {NAME}"),
            format!("{digest}  {NAME}\r\n"),
            format!("{digest} {NAME}\n"),
        ] {
            assert!(parse_checksum(invalid.as_bytes(), NAME).is_err());
        }
        let fixture = Fixture::new(|_, _| ok(b"[]"));
        let client = fixture.client(true, Duration::from_secs(3));
        let mut output = Vec::new();
        let expected = Sha256::digest(b"abcd").into();
        assert!(
            client
                .copy_verified(&mut &b"abcd"[..], &mut output, expected, 3)
                .is_err()
        );
        assert!(output.is_empty());
        assert!(
            client
                .copy_verified(&mut &b"abcd"[..], &mut output, [0; 32], 4)
                .is_err()
        );
        assert_eq!(output, b"abcd");
    }

    #[test]
    fn production_url_contract_rejects_other_origins_paths_and_userinfo() {
        // No HTTP request is issued by URL validation.
        let client = Client::new().unwrap();
        let good = format!("https://github.com{ASSET_PATH}{TAG}/{NAME}");
        assert!(client.asset_url(&good).is_ok());
        for bad in [
            good.replace("https:", "http:"),
            good.replace("github.com", "github.com:444"),
            good.replace("github.com", "@github.com"),
            good.replace("github.com", "github.com.attacker.invalid"),
            good.replace("vproxy/releases", "other/releases"),
            format!("{good}?secret=hidden"),
            format!("{good}#fragment"),
            good.replace(TAG, ".."),
        ] {
            assert!(client.asset_url(&bad).is_err());
        }
        for good in [
            "https://github.com/redirect",
            "https://release-assets.githubusercontent.com/signed?secret=hidden",
            "https://objects.githubusercontent.com/signed",
        ] {
            assert!(client.check_redirect(&Url::parse(good).unwrap()).is_ok());
        }
        assert!(
            client
                .check_redirect(
                    &Url::parse(
                        "https://release-assets.githubusercontent.com.attacker.invalid/signed"
                    )
                    .unwrap()
                )
                .is_err()
        );
    }
}
