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
}

impl Client {
    pub(super) fn new() -> io::Result<Self> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::build(roots, TOTAL)
    }

    fn build(roots: rustls::RootCertStore, budget: Duration) -> io::Result<Self> {
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
        let builder = reqwest::Client::builder()
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
        let http = reqwest::blocking::ClientBuilder::from(builder)
            .timeout(budget)
            .build()
            .map_err(|_| io::Error::other("cannot create update HTTP client"))?;
        Ok(Self { http, deadline })
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
        Url::parse(API).map_err(|_| invalid("invalid compiled update metadata URL"))
    }

    fn asset_prefix(&self) -> String {
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

    use super::*;

    const NAME: &str = "vproxy-99.0.0-x86_64-unknown-linux-musl.tar.gz";

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
        let client = Client::new().unwrap();
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
}
