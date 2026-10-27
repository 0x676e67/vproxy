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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    fn request(path: &str, encoding: Option<&str>, method: Method) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(value) = encoding {
            headers.insert(header::ACCEPT_ENCODING, value.parse().unwrap());
        }
        response(&method, &path.parse().unwrap(), &headers).unwrap()
    }

    #[test]
    fn encoding_weights_respect_identity_wildcards_and_exclusions() {
        for (value, expected) in [
            ("", (1000, 0, 0)),
            ("gzip, br", (1000, 1000, 1000)),
            ("*;q=0", (0, 0, 0)),
            ("*;q=0, identity;q=0.5, br;q=1", (500, 0, 1000)),
            ("*;q=0.7, gzip;q=0", (1000, 0, 700)),
            ("GZip;Q=0.125, identity;q=0", (0, 125, 0)),
            ("unknown, br;q=0.", (1000, 0, 0)),
            ("gzip;q=0, gzip, x-gzip", (1000, 0, 0)),
            ("br, br", (1000, 0, 1000)),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, value.parse().unwrap());
            let preferences = Preferences::parse(&headers).unwrap();
            assert_eq!(
                (preferences.identity, preferences.gzip, preferences.br),
                expected,
                "{value}"
            );
        }
        for value in [
            "br;q=.5",
            "br;q=1.001",
            "br;q=0.0001",
            "br;q=NaN",
            "br;q=1e0",
            "br;level=1",
            "br;q=0;q=1",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT_ENCODING, value.parse().unwrap());
            assert!(Preferences::parse(&headers).is_err(), "{value}");
        }
        let mut headers = HeaderMap::new();
        headers.append(header::ACCEPT_ENCODING, "gzip;q=0.5".parse().unwrap());
        headers.append(header::ACCEPT_ENCODING, "br, identity;q=0".parse().unwrap());
        let preferences = Preferences::parse(&headers).unwrap();
        assert_eq!(
            (preferences.identity, preferences.gzip, preferences.br),
            (0, 500, 1000)
        );
    }

    #[tokio::test]
    async fn encoded_assets_head_and_conditional_get_have_consistent_headers() {
        let identity = request("/", None, Method::GET);
        assert_eq!(identity.status(), StatusCode::OK);
        assert_eq!(identity.headers()[header::CACHE_CONTROL], "no-cache");
        assert!(!identity.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(identity.headers()[header::VARY], "Accept-Encoding");
        assert!(
            identity.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        let identity_tag = identity.headers()[header::ETAG].clone();
        let identity_length = identity.headers()[header::CONTENT_LENGTH].clone();
        let bytes = identity.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.starts_with(b"<!DOCTYPE html>"));

        let encoded = request("/index.html", Some("gzip, br"), Method::GET);
        assert_eq!(encoded.headers()[header::CONTENT_ENCODING], "br");
        assert_ne!(encoded.headers()[header::ETAG], identity_tag);
        let encoded_tag = encoded.headers()[header::ETAG].clone();
        let encoded_length = encoded.headers()[header::CONTENT_LENGTH].clone();
        let encoded_body = encoded.into_body().collect().await.unwrap().to_bytes();
        assert!(!encoded_body.is_empty());

        let head = request("/index.html", Some("br"), Method::HEAD);
        assert_eq!(head.headers()[header::CONTENT_LENGTH], encoded_length);
        assert_eq!(head.headers()[header::ETAG], encoded_tag);
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let head = request("/", None, Method::HEAD);
        assert_eq!(head.headers()[header::CONTENT_LENGTH], identity_length);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            format!("\"other\", W/{}", identity_tag.to_str().unwrap())
                .parse()
                .unwrap(),
        );
        let cached = response(&Method::GET, &"/".parse().unwrap(), &headers).unwrap();
        assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(cached.headers()[header::ETAG], identity_tag);
        assert!(!cached.headers().contains_key(header::CONTENT_LENGTH));
        assert!(
            cached
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        // Strong If-Match is evaluated before a matching weak If-None-Match.
        headers.insert(
            header::IF_MATCH,
            format!("W/{}", identity_tag.to_str().unwrap())
                .parse()
                .unwrap(),
        );
        let failed = response(&Method::GET, &"/".parse().unwrap(), &headers).unwrap();
        assert_eq!(failed.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(failed.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!failed.headers().contains_key(header::CONTENT_ENCODING));
        headers.insert(header::IF_MATCH, identity_tag.clone());
        assert_eq!(
            response(&Method::GET, &"/".parse().unwrap(), &headers)
                .unwrap()
                .status(),
            StatusCode::NOT_MODIFIED
        );
        headers.remove(header::IF_NONE_MATCH);
        headers.insert(header::IF_MATCH, "*".parse().unwrap());
        assert_eq!(
            response(&Method::HEAD, &"/".parse().unwrap(), &headers)
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[test]
    fn malformed_conditional_tags_ignore_the_entire_combined_field() {
        let tag = request("/", None, Method::GET).headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        for name in [header::IF_MATCH, header::IF_NONE_MATCH] {
            for value in [
                "\"bad tag\"".to_owned(),
                "W/\"bad\ttag\"".to_owned(),
                "\"unfinished".to_owned(),
                format!("\"bad tag\", {tag}"),
                format!("{tag}, \"bad tag\""),
                format!("{tag}, invalid"),
                format!("{tag}, w/{tag}"),
                format!("{tag} {tag}"),
                format!("*, {tag}"),
                format!("{tag}, *"),
                "*, *".to_owned(),
            ] {
                let mut headers = HeaderMap::new();
                headers.insert(name.clone(), value.parse().unwrap());
                assert_eq!(
                    response(&Method::GET, &"/".parse().unwrap(), &headers)
                        .unwrap()
                        .status(),
                    StatusCode::OK,
                    "{name}: {value:?}"
                );
            }
            // Combining lines inserts ", ", whose SP cannot be inside a tag.
            let mut headers = HeaderMap::new();
            headers.append(name.clone(), "\"split".parse().unwrap());
            headers.append(name.clone(), "tag\"".parse().unwrap());
            assert_eq!(
                response(&Method::GET, &"/".parse().unwrap(), &headers)
                    .unwrap()
                    .status(),
                StatusCode::OK,
                "{name}: cross-field tag"
            );
            // A match in an earlier field cannot hide invalid input in a later one.
            headers.clear();
            headers.append(name.clone(), tag.parse().unwrap());
            headers.append(name.clone(), "invalid".parse().unwrap());
            assert_eq!(
                response(&Method::GET, &"/".parse().unwrap(), &headers)
                    .unwrap()
                    .status(),
                StatusCode::OK,
                "{name}: malformed later field"
            );
        }
    }

    #[test]
    fn conditional_tags_preserve_opaque_commas_and_optional_whitespace() {
        let tag = request("/", None, Method::GET).headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        for (name, expected) in [
            (header::IF_MATCH, StatusCode::OK),
            (header::IF_NONE_MATCH, StatusCode::NOT_MODIFIED),
        ] {
            let mut headers = HeaderMap::new();
            headers.append(name.clone(), " \t\"other,tag\\\"\t ".parse().unwrap());
            headers.append(name.clone(), format!("\t{tag} ").parse().unwrap());
            assert_eq!(
                response(&Method::GET, &"/".parse().unwrap(), &headers)
                    .unwrap()
                    .status(),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn conditional_tag_lists_distinguish_absent_empty_weak_and_nonmatching_values() {
        assert_eq!(
            condition_matches(&HeaderMap::new(), header::IF_MATCH, b"\"current\"", true),
            None
        );
        for (values, strong, weak) in [
            (vec![b"".as_slice()], Some(false), Some(false)),
            (vec![b", \t,,".as_slice()], Some(false), Some(false)),
            (vec![b"\"current\"".as_slice()], Some(true), Some(true)),
            (vec![b"W/\"current\"".as_slice()], Some(false), Some(true)),
            (vec![b"w/\"current\"".as_slice()], None, None),
            (vec![b"W/ \"current\"".as_slice()], None, None),
            (vec![b"\"other\"".as_slice()], Some(false), Some(false)),
            (vec![b" \t*\t ".as_slice()], Some(true), Some(true)),
            (vec![b",*".as_slice()], None, None),
            (vec![b"*,".as_slice()], None, None),
            (vec![b"*".as_slice(), b"".as_slice()], None, None),
            (
                vec![b"\"other\",".as_slice(), b", W/\"current\", ".as_slice()],
                Some(false),
                Some(true),
            ),
            (
                vec![b"\"other\", \"current\"".as_slice(), b", \t".as_slice()],
                Some(true),
                Some(true),
            ),
            (vec![b"\"bad\\\"quote\"".as_slice()], None, None),
        ] {
            let mut headers = HeaderMap::new();
            for value in &values {
                headers.append(header::IF_MATCH, HeaderValue::from_bytes(value).unwrap());
            }
            assert_eq!(
                condition_matches(&headers, header::IF_MATCH, b"\"current\"", true),
                strong,
                "strong: {values:?}"
            );
            assert_eq!(
                condition_matches(&headers, header::IF_MATCH, b"\"current\"", false),
                weak,
                "weak: {values:?}"
            );
        }
        // An empty opaque tag is a real validator, unlike an empty list element.
        for value in ["\"\"", "W/\"\""] {
            let mut headers = HeaderMap::new();
            headers.insert(header::IF_NONE_MATCH, value.parse().unwrap());
            assert_eq!(
                condition_matches(&headers, header::IF_NONE_MATCH, b"\"\"", false),
                Some(true)
            );
        }
    }

    #[test]
    fn conditional_tag_lists_preserve_obs_text_and_real_matches() {
        let tag = request("/", None, Method::GET).headers()[header::ETAG].clone();
        for (name, matching, nonmatching) in [
            (
                header::IF_MATCH,
                StatusCode::OK,
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                header::IF_NONE_MATCH,
                StatusCode::NOT_MODIFIED,
                StatusCode::OK,
            ),
        ] {
            for combined in [false, true] {
                let mut headers = HeaderMap::new();
                let mut value = b"\"other\x80\xff\"".to_vec();
                if combined {
                    value.extend_from_slice(b", ");
                    value.extend_from_slice(tag.as_bytes());
                    headers.insert(name.clone(), HeaderValue::from_bytes(&value).unwrap());
                } else {
                    headers.append(name.clone(), HeaderValue::from_bytes(&value).unwrap());
                    headers.append(name.clone(), tag.clone());
                }
                assert_eq!(
                    response(&Method::GET, &"/".parse().unwrap(), &headers)
                        .unwrap()
                        .status(),
                    matching,
                    "{name}: combined={combined}"
                );
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                name.clone(),
                HeaderValue::from_bytes(b"\"other\x80\xff\"").unwrap(),
            );
            assert_eq!(
                response(&Method::GET, &"/".parse().unwrap(), &headers)
                    .unwrap()
                    .status(),
                nonmatching,
                "{name}: obs-text without a match"
            );
        }
    }

    #[test]
    fn generated_namespace_has_no_filesystem_or_spa_fallback() {
        for path in [
            "/missing.js",
            "/api/v1/unknown",
            "/vproxy-web.json",
            "/index.html.br",
            "/../index.html",
            "/%69ndex.html",
            "//index.html",
            "/.private",
            "/nested/../index.html",
        ] {
            assert!(
                response(&Method::GET, &path.parse().unwrap(), &HeaderMap::new()).is_none(),
                "{path}"
            );
        }
        assert_eq!(
            request("/", Some("*;q=0"), Method::GET).status(),
            StatusCode::NOT_ACCEPTABLE
        );
        let disallowed = request("/", None, Method::POST);
        assert_eq!(disallowed.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(disallowed.headers()[header::ALLOW], "GET, HEAD");

        let script = Assets::iter()
            .find(|path| path.ends_with(".js") && hashed_name(path))
            .unwrap();
        let response = request(&format!("/{script}"), None, Method::GET);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
    }
}
