//! Immutable, build-verified browser assets. No request can access the host
//! filesystem; even debug builds embed bytes so deployments need only one binary.

use std::borrow::Cow;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use rust_embed::RustEmbed;

/// Only this generated directory is embedded. `build.rs` rejects stale, demo or
/// mixed output before the derive runs; its manifest is never a public asset.
#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Assets;

const CONTENT_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

/// Return a known public asset or let the API fallback produce its normal 404.
/// Hash routing needs no wildcard HTML rewrite: unknown API/asset paths must not
/// silently become successful HTML. Percent-encoded and dot paths are not part
/// of the generated public namespace and are never decoded into filesystem paths.
pub(super) fn response(method: &Method, uri: &Uri, headers: &HeaderMap) -> Option<Response> {
    let path = match uri.path() {
        "/" => "index.html",
        path => path.strip_prefix('/')?,
    };
    if path.contains(['%', '\\'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.'))
        || path == "vproxy-web.json"
    {
        return None;
    }
    let content_type = content_type(path)?;
    let identity = Assets::get(path)?;
    if !matches!(*method, Method::GET | Method::HEAD) {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Some(response);
    }
    let preferences = match Preferences::parse(headers) {
        Ok(value) => value,
        Err(()) => return Some(StatusCode::BAD_REQUEST.into_response()),
    };
    let mut selected = (preferences.identity, None, identity);
    for (coding, suffix, quality) in [
        ("gzip", ".gz", preferences.gzip),
        ("br", ".br", preferences.br),
    ] {
        if quality > 0
            && quality >= selected.0
            && let Some(asset) = Assets::get(&format!("{path}{suffix}"))
        {
            selected = (quality, Some(coding), asset);
        }
    }
    if selected.0 == 0 {
        let mut response = StatusCode::NOT_ACCEPTABLE.into_response();
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        return Some(response);
    }
    let (_, coding, asset) = selected;
    // Strong validators describe encoded bytes, not just the source file:
    // https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.3
    let digest = asset.metadata.sha256_hash();
    let mut tag = String::with_capacity(66);
    tag.push('"');
    for byte in digest {
        use std::fmt::Write as _;
        // Formatting into a String cannot fail; avoid a fallible format sink.
        let _ = write!(tag, "{byte:02x}");
    }
    tag.push('"');
    let Ok(etag) = HeaderValue::from_str(&tag) else {
        return Some(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    // If-Match precedes If-None-Match and uses strong comparison, including on
    // safe methods: https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2.2
    let failed = condition_matches(headers, header::IF_MATCH, etag.as_bytes(), true) == Some(false);
    let unchanged = !failed
        && condition_matches(headers, header::IF_NONE_MATCH, etag.as_bytes(), false) == Some(true);
    let length = asset.data.len();
    let body = if failed || unchanged || *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(match asset.data {
            Cow::Borrowed(value) => Bytes::from_static(value),
            Cow::Owned(value) => Bytes::from(value),
        })
    };
    let mut response = Response::new(body);
    if failed {
        *response.status_mut() = StatusCode::PRECONDITION_FAILED;
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    } else if unchanged {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
    } else if let Ok(length) = HeaderValue::from_str(&length.to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length);
    }
    let output = response.headers_mut();
    output.insert(header::ETAG, etag);
    output.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    output.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    output.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_POLICY),
    );
    output.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if failed {
            "no-store"
        } else if hashed_name(path) {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    if !failed && let Some(coding) = coding {
        output.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    Some(response)
}

/// Match a static GET/HEAD condition against our generated strong, quoted tag.
/// `None` means absent or malformed input: ignore the entire combined field,
/// never an already-matched prefix. `Some(false)` is a valid nonmatching list,
/// including an empty list; `Some(true)` also covers a standalone wildcard since
/// this function is called only after the representation has been found.
/// If-Match requires strong comparison; If-None-Match permits weak comparison.
/// https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1
/// https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2
///
/// Parse bytes rather than UTF-8: `etagc` includes obs-text, and commas/backslashes
/// inside an opaque tag are ordinary octets, not separators or escapes.
/// https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3
fn condition_matches(
    headers: &HeaderMap,
    name: header::HeaderName,
    current_tag: &[u8],
    strong: bool,
) -> Option<bool> {
    let fields = headers.get_all(name);
    let mut values = fields.iter();
    let first = values.next()?;
    if let Some(rest) = trim_ows(first.as_bytes()).strip_prefix(b"*") {
        // A wildcard is not a list member, even alongside another wildcard or
        // an empty field: combining lines would introduce a comma after it.
        return (trim_ows(rest).is_empty() && values.next().is_none()).then_some(true);
    }
    let mut matched = false;
    for value in std::iter::once(first).chain(values) {
        let mut rest = value.as_bytes();
        loop {
            rest = trim_ows(rest);
            if rest.is_empty() {
                break;
            }
            // Ignore empty list elements as required for recipients. Work is
            // linear in the request's already-bounded HTTP header bytes.
            // https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2
            if let Some(tail) = rest.strip_prefix(b",") {
                rest = tail;
                continue;
            }
            let (weak, quoted) = match rest.strip_prefix(b"W/") {
                Some(value) => (true, value),
                None => (false, rest),
            };
            let opaque = quoted.strip_prefix(b"\"")?;
            let end = opaque.iter().position(|&byte| {
                byte == b'"' || !(byte == b'!' || (b'#'..=b'~').contains(&byte) || byte >= 0x80)
            })?;
            if opaque.get(end) != Some(&b'"') {
                return None;
            }
            let (candidate, tail) = quoted.split_at_checked(end.checked_add(2)?)?;
            matched |= (!strong || !weak) && candidate == current_tag;
            rest = trim_ows(tail);
            if rest.is_empty() {
                break;
            }
            rest = rest.strip_prefix(b",")?;
        }
        // Each line ends outside a tag. An unfinished tag cannot span lines:
        // the conceptual combining separator ", " includes SP, not etagc.
    }
    Some(matched)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    value
}

/// Generated assets have a small explicit MIME allowlist. In particular, build
/// metadata, compressed sidecars and source maps cannot be downloaded directly.
fn content_type(path: &str) -> Option<&'static str> {
    match path.rsplit('.').next()? {
        "html" if path == "index.html" => Some("text/html; charset=utf-8"),
        "js" => Some("text/javascript; charset=utf-8"),
        "css" => Some("text/css; charset=utf-8"),
        "json" => Some("application/json"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        "woff2" => Some("font/woff2"),
        _ => None,
    }
}

fn hashed_name(path: &str) -> bool {
    path.split('.')
        .any(|part| part.len() >= 8 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Quality values are integer thousandths, avoiding float rounding around q=0.
/// An absent field deliberately selects identity; explicit wildcard/identity
/// exclusions are respected. Unknown valid codings are harmlessly ignored.
/// https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3
struct Preferences {
    identity: u16,
    gzip: u16,
    br: u16,
}

impl Preferences {
    fn parse(headers: &HeaderMap) -> Result<Self, ()> {
        let (mut identity, mut gzip, mut br, mut wildcard) =
            (None::<u16>, None::<u16>, None::<u16>, None::<u16>);
        for value in headers.get_all(header::ACCEPT_ENCODING) {
            for item in value.to_str().map_err(|_| ())?.split(',') {
                let item = item.trim_matches([' ', '\t']);
                if item.is_empty() {
                    continue;
                }
                let (coding, quality) = match item.split_once(';') {
                    Some((coding, weight)) => {
                        let (name, value) =
                            weight.trim_matches([' ', '\t']).split_once('=').ok_or(())?;
                        if !name.eq_ignore_ascii_case("q") {
                            return Err(());
                        }
                        (coding.trim_end_matches([' ', '\t']), quality(value)?)
                    }
                    None => (item, 1000),
                };
                if coding.is_empty()
                    || !coding.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
                    })
                {
                    return Err(());
                }
                let slot = if coding.eq_ignore_ascii_case("identity") {
                    &mut identity
                } else if coding.eq_ignore_ascii_case("gzip")
                    || coding.eq_ignore_ascii_case("x-gzip")
                {
                    &mut gzip
                } else if coding.eq_ignore_ascii_case("br") {
                    &mut br
                } else if coding == "*" {
                    &mut wildcard
                } else {
                    continue;
                };
                // Duplicate weights have no specified tie-breaker. Retain the
                // conservative minimum, including q=0, across combined lines.
                *slot = Some(slot.map_or(quality, |previous| previous.min(quality)));
            }
        }
        Ok(Self {
            identity: identity.unwrap_or(if wildcard == Some(0) { 0 } else { 1000 }),
            gzip: gzip.or(wildcard).unwrap_or(0),
            br: br.or(wildcard).unwrap_or(0),
        })
    }
}

fn quality(value: &str) -> Result<u16, ()> {
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(integer, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || integer == "1" && fraction.bytes().any(|byte| byte != b'0')
    {
        return Err(());
    }
    if integer == "1" {
        return Ok(1000);
    }
    let mut result = 0;
    for (index, byte) in fraction.bytes().enumerate() {
        result += u16::from(byte - b'0') * [100, 10, 1][index];
    }
    Ok(result)
}
