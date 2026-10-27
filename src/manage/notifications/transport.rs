//! HTTPS-only, direct delivery with per-attempt DNS admission and pinning.
//! A URL is administrator authority, but cannot turn this endpoint into a
//! loopback/private-network fetcher. Redirects, proxies and implicit retries
//! are disabled; response bodies and raw transport errors are never retained.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    redirect::Policy,
};
use rustls::{ClientConfig, RootCertStore, client::Resumption, crypto::aws_lc_rs};
use url::{Host, Url};

use super::{Destination, Outcome};

pub(super) const DEADLINE: Duration = Duration::from_secs(10);

pub(in crate::manage) fn validate(destination: &Destination) -> bool {
    let Ok(url) = Url::parse(&destination.url) else {
        return false;
    };
    destination.url.len() <= 2048
        && !destination.url.chars().any(char::is_control)
        && url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && destination.url.split_once("://").is_some_and(|(_, rest)| {
            !rest
                .split(['/', '?', '#', '\\'])
                .next()
                .unwrap_or_default()
                .contains('@')
        })
        && url.fragment().is_none()
        && url.port() != Some(0)
        && destination.bearer.len() <= 1024
        && valid_bearer(&destination.bearer)
        && match url.host() {
            Some(Host::Ipv4(ip)) => public(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => public(IpAddr::V6(ip)),
            Some(Host::Domain(name)) => name != "localhost" && !name.ends_with(".localhost"),
            None => false,
        }
}

/// RFC 6750 §2.1 b64token permits padding only after its nonempty alphabet.
/// https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
fn valid_bearer(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let token = value.trim_end_matches('=');
    !token.is_empty()
        && token
            .bytes()
            .all(|v| matches!(v, b'A'..=b'Z'|b'a'..=b'z'|b'0'..=b'9'|b'-'|b'.'|b'_'|b'~'|b'+'|b'/'))
}

/// Conservative destination policy based on the IANA special-purpose address
/// registries. Exceptions within special blocks are deliberately not admitted.
/// IPv6 is native global unicast only: no mapped/translated, ULA or tunnel forms.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192 && (b == 0 && (c == 0 || c == 2) || b == 168 || b == 88 && c == 99))
                && !(a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (0x2000..=0x3fff).contains(&s[0])
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}

fn builder(roots: RootCertStore) -> Option<reqwest::ClientBuilder> {
    // Explicit provider: reqwest deliberately has no process-global provider
    // feature, and tests/embedded callers need the same AWS-LC boundary as main.
    let mut tls = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.resumption = Resumption::disabled();
    tls.enable_early_data = false;
    Some(
        Client::builder()
            .https_only(true)
            .use_preconfigured_tls(tls)
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(3))
            .timeout(DEADLINE),
    )
}

/// DNS answers are bounded, all must pass admission, and only those exact
/// addresses reach reqwest. The original URL still supplies Host and TLS SNI.
async fn client(destination: &Destination) -> Result<Client, Outcome> {
    if !validate(destination) {
        return Err(Outcome::DestinationBlocked);
    }
    let url = Url::parse(&destination.url).map_err(|_| Outcome::DestinationBlocked)?;
    let port = url
        .port_or_known_default()
        .ok_or(Outcome::DestinationBlocked)?;
    let mut builder = builder(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
    .ok_or(Outcome::Unknown)?;
    if let Some(Host::Domain(name)) = url.host() {
        // Resolver availability is not a policy rejection. The conservative
        // Unknown batch state can use the opted-in deduplicated retry budget.
        let resolved = tokio::net::lookup_host((name, port))
            .await
            .map_err(|_| Outcome::Unknown)?;
        let addresses = pinned(resolved)?;
        builder = builder.resolve_to_addrs(name, &addresses);
    }
    builder.build().map_err(|_| Outcome::Unknown)
}

fn pinned(resolved: impl Iterator<Item = SocketAddr>) -> Result<Vec<SocketAddr>, Outcome> {
    let mut addresses = Vec::new();
    for address in resolved.take(17) {
        if !public(address.ip()) || addresses.len() == 16 {
            return Err(Outcome::DestinationBlocked);
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err(Outcome::Unknown);
    }
    Ok(addresses)
}

pub(super) async fn send(
    destination: &Destination,
    body: &[u8],
    id: &str,
) -> (Outcome, Option<u16>) {
    tokio::time::timeout(DEADLINE, async {
        let client = match client(destination).await {
            Ok(client) => client,
            Err(outcome) => return (outcome, None),
        };
        post(client, destination, body, id).await
    })
    .await
    .unwrap_or((Outcome::Unknown, None))
}

async fn post(
    client: Client,
    destination: &Destination,
    body: &[u8],
    id: &str,
) -> (Outcome, Option<u16>) {
    let mut request = client
        .post(&destination.url)
        .header(CONTENT_TYPE, "application/json")
        .header("vproxy-delivery-id", id)
        .body(body.to_vec());
    if !destination.bearer.is_empty() {
        let Ok(mut header) = HeaderValue::from_str(&format!("Bearer {}", destination.bearer))
        else {
            return (Outcome::DestinationBlocked, None);
        };
        header.set_sensitive(true);
        request = request.header(AUTHORIZATION, header);
    }
    match request.send().await {
        // Headers suffice for acceptance; never buffer an untrusted response body.
        Ok(response) => {
            let code = response.status();
            (
                if code.is_success() {
                    Outcome::Accepted
                } else if response
                    .headers()
                    .contains_key(reqwest::header::RETRY_AFTER)
                {
                    // RFC 9110 §10.2.3: never replace the receiver's delay with
                    // our shorter backoff. Pause for review, including malformed
                    // or duplicate Retry-After; raw header values stay private.
                    // https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
                    Outcome::Deferred
                } else {
                    Outcome::Rejected
                },
                Some(code.as_u16()),
            )
        }
        Err(_) => (Outcome::Unknown, None),
    }
}

#[cfg(test)]
pub(super) async fn send_test(
    client: Client,
    destination: &Destination,
    body: &[u8],
    id: &str,
) -> (Outcome, Option<u16>) {
    post(client, destination, body, id).await
}

#[cfg(test)]
pub(super) fn test_builder(roots: RootCertStore) -> Option<reqwest::ClientBuilder> {
    builder(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_admission_rejects_mixed_or_oversized_answers_without_a_fallback_lookup() {
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let private: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            pinned([public, private].into_iter()).err(),
            Some(Outcome::DestinationBlocked)
        );
        assert_eq!(
            pinned(std::iter::repeat_n(public, 17)).err(),
            Some(Outcome::DestinationBlocked)
        );
        assert_eq!(pinned(std::iter::empty()).err(), Some(Outcome::Unknown));
        let addresses = vec![public, "[2606:4700:4700::1111]:443".parse().unwrap()];
        assert_eq!(pinned(addresses.clone().into_iter()).unwrap(), addresses);
    }
}
