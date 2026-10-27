//! Small, single-use client state machine. Hyper owns HTTP parsing/upgrades;
//! SOCKS reads exact fields so no tunnel byte is lost at a reply boundary.

use std::{future::Future, io, path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::FutureExt as _;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, client::Resumption, crypto::aws_lc_rs};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use super::{
    CONNECT_TIMEOUT, Code, Profile, Protocol, Report, Stage, TARGET_AUTHORITY, TARGET_HOST,
};

type Result<T> = std::result::Result<T, (Code, Option<u16>)>;

/// One cold-path allocation per stream layer; never used by proxy workers.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = Box<dyn Io>;

/// Independent root stores. A private proxy CA must not authorize the website.
pub(super) struct Trust {
    proxy: Arc<ClientConfig>,
    target: Arc<ClientConfig>,
}

impl Trust {
    pub(super) fn load(proxy_ca: Option<&Path>) -> io::Result<Self> {
        let public = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let proxy = if let Some(path) = proxy_ca {
            let pem = super::super::files::read(path, 256 * 1024, false)
                .map_err(|_| super::input("cannot read proxy CA file"))?;
            let mut roots = RootCertStore::empty();
            for item in rustls_pemfile::read_all(&mut pem.as_slice()) {
                let rustls_pemfile::Item::X509Certificate(certificate) =
                    item.map_err(|_| super::input("invalid proxy CA file"))?
                else {
                    return Err(super::input("proxy CA file must contain only certificates"));
                };
                roots
                    .add(certificate)
                    .map_err(|_| super::input("invalid proxy CA certificate"))?;
            }
            if roots.is_empty() {
                return Err(super::input("proxy CA file has no certificates"));
            }
            roots
        } else {
            public.clone()
        };
        Ok(Self {
            proxy: config(proxy)?,
            target: config(public)?,
        })
    }
}

/// Normal AWS-LC certificate/name validation, TLS 1.2/1.3 and HTTP/1.1 only.
/// Resumption and early data are disabled for both newly-created client layers.
fn config(roots: RootCertStore) -> io::Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| super::input("cannot configure connection test TLS"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Dropping this future closes the entire pipeline. Only proxy DNS is resolved
/// locally; SOCKS carries example.com as a domain for proxy-side resolution.
pub(super) async fn execute(
    profile: &Profile,
    server_name: ServerName<'static>,
    password: &[u8],
    trust: Trust,
    report: &mut Report,
    stage: &mut Stage,
) -> Result<()> {
    *stage = Stage::ProxyTcp;
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((profile.host.as_str(), profile.port)),
    )
    .await
    .map_err(|_| (Code::Timeout, None))?
    .map_err(|_| (Code::TcpFailed, None))?;
    report.pass(*stage, None);
    let stream: Stream = if profile.protocol == Protocol::Https {
        *stage = Stage::ProxyTls;
        let stream = TlsConnector::from(trust.proxy)
            .connect(server_name, stream)
            .await
            .map_err(|_| (Code::TlsFailed, None))?;
        report.pass(*stage, None);
        Box::new(stream)
    } else {
        Box::new(stream)
    };
    *stage = Stage::ProxyTunnel;
    let stream = match profile.protocol {
        Protocol::Http | Protocol::Https => {
            http_tunnel(stream, &profile.username, password).await?
        }
        Protocol::Socks5 => socks_tunnel(stream, &profile.username, password).await?,
    };
    report.pass(*stage, None);
    *stage = Stage::TargetTls;
    let server_name = ServerName::try_from(TARGET_HOST).map_err(|_| (Code::TlsFailed, None))?;
    let stream = TlsConnector::from(trust.target)
        .connect(server_name, stream)
        .await
        .map_err(|_| (Code::TlsFailed, None))?;
    report.pass(*stage, None);
    *stage = Stage::TargetHttp;
    let status = target_response(Box::new(stream)).await?;
    report.pass(*stage, Some(status));
    Ok(())
}

/// Sensitive marking prevents ordinary HeaderValue Debug output, not erasure of
/// Hyper/TLS-owned copies. Caller-owned plaintext and Base64 buffers zeroize.
fn authorization(username: &str, password: &[u8]) -> Result<HeaderValue> {
    let length = username
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(password.len()))
        .ok_or((Code::HttpFailed, None))?;
    let mut plain = Zeroizing::new(Vec::with_capacity(length));
    plain.extend_from_slice(username.as_bytes());
    plain.push(b':');
    plain.extend_from_slice(password);
    let length = base64::encoded_len(length, true)
        .and_then(|length| length.checked_add(6))
        .ok_or((Code::HttpFailed, None))?;
    let mut encoded = Zeroizing::new(String::with_capacity(length));
    encoded.push_str("Basic ");
    STANDARD.encode_string(&plain, &mut encoded);
    let mut value =
        HeaderValue::from_bytes(encoded.as_bytes()).map_err(|_| (Code::HttpFailed, None))?;
    value.set_sensitive(true);
    Ok(value)
}

fn builder() -> hyper::client::conn::http1::Builder {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(16 * 1024).max_headers(64);
    builder
}

/// RFC 9110 §9.3.6: any 2xx upgrades immediately, ignoring CL/TE. Hyper's
/// upgrade retains over-read bytes; it must be driven through with_upgrades().
/// <https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6>
async fn http_tunnel(stream: Stream, username: &str, password: &[u8]) -> Result<Stream> {
    let (mut sender, connection) = builder()
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (Code::HttpFailed, None))?;
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri(TARGET_AUTHORITY)
        .header(header::HOST, TARGET_AUTHORITY)
        .header(
            header::PROXY_AUTHORIZATION,
            authorization(username, password)?,
        )
        .body(Full::new(Bytes::new()))
        .map_err(|_| (Code::HttpFailed, None))?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (Code::HttpFailed, None))?;
        let status = response.status();
        if !status.is_success() {
            return Err((
                if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    Code::AuthenticationRejected
                } else {
                    Code::TunnelRejected
                },
                Some(status.as_u16()),
            ));
        }
        hyper::upgrade::on(response)
            .await
            .map(|stream| Box::new(TokioIo::new(stream)) as Stream)
            .map_err(|_| (Code::HttpFailed, None))
    };
    drive(exchange, connection.with_upgrades()).await
}

/// RFC 1928 §3 and RFC 1929 §2: offer only username/password. An unsolicited
/// NO AUTH selection cannot prove these credentials were checked. No retries.
/// <https://www.rfc-editor.org/rfc/rfc1928.html#section-3>
/// <https://www.rfc-editor.org/rfc/rfc1929.html#section-2>
async fn socks_tunnel(mut stream: Stream, username: &str, password: &[u8]) -> Result<Stream> {
    let user_len = u8::try_from(username.len()).map_err(|_| (Code::InvalidResponse, None))?;
    let password_len = u8::try_from(password.len()).map_err(|_| (Code::InvalidResponse, None))?;
    stream
        .write_all(&[5, 1, 2])
        .await
        .map_err(|_| (Code::IoFailed, None))?;
    let mut reply = [0; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| (Code::InvalidResponse, None))?;
    match reply {
        [5, 2] => {}
        [5, 255] => return Err((Code::MethodRejected, None)),
        _ => return Err((Code::InvalidResponse, None)),
    }
    let mut auth = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
    auth.extend_from_slice(&[1, user_len]);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password_len);
    auth.extend_from_slice(password);
    stream
        .write_all(&auth)
        .await
        .map_err(|_| (Code::IoFailed, None))?;
    drop(auth);
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| (Code::InvalidResponse, None))?;
    if reply[0] != 1 {
        return Err((Code::InvalidResponse, None));
    }
    if reply[1] != 0 {
        return Err((Code::AuthenticationRejected, Some(u16::from(reply[1]))));
    }
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(TARGET_HOST.as_bytes());
    request.extend_from_slice(&443_u16.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| (Code::IoFailed, None))?;
    let mut head = [0; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| (Code::InvalidResponse, None))?;
    if head[0] != 5 || head[2] != 0 || head[1] > 8 {
        return Err((Code::InvalidResponse, None));
    }
    if head[1] != 0 {
        return Err((Code::TunnelRejected, Some(u16::from(head[1]))));
    }
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| (Code::InvalidResponse, None))?;
            if length == 0 {
                return Err((Code::InvalidResponse, None));
            }
            usize::from(length)
        }
        _ => return Err((Code::InvalidResponse, None)),
    };
    let mut tail = [0; 257];
    stream
        .read_exact(&mut tail[..length + 2])
        .await
        .map_err(|_| (Code::InvalidResponse, None))?;
    Ok(stream)
}

/// Read only the final response headers. No body/Location is logged or followed.
async fn target_response(stream: Stream) -> Result<u16> {
    let (mut sender, connection) = builder()
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (Code::HttpFailed, None))?;
    let request = Request::builder()
        .uri("/")
        .header(header::HOST, TARGET_HOST)
        .header(header::CONNECTION, "close")
        .header(header::USER_AGENT, "vproxy-connection-test")
        .body(Full::new(Bytes::new()))
        .map_err(|_| (Code::HttpFailed, None))?;
    let exchange = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| (Code::HttpFailed, None))?;
        let status = response.status();
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            Err((
                if status.is_redirection() {
                    Code::RedirectNotFollowed
                } else {
                    Code::TargetRejected
                },
                Some(status.as_u16()),
            ))
        }
    };
    drive(exchange, connection).await
}

/// Poll driver and exchange in this future, never a detached task. A clean close
/// can deliver a buffered response before the driver finishes; consume it first.
async fn drive<T>(
    exchange: impl Future<Output = Result<T>>,
    driver: impl Future<Output = std::result::Result<(), hyper::Error>>,
) -> Result<T> {
    tokio::pin!(exchange, driver);
    tokio::select! {
        biased;
        result = &mut exchange => result,
        result = &mut driver => match result {
            Ok(()) => exchange.await,
            Err(_) => exchange.as_mut().now_or_never().unwrap_or(Err((Code::HttpFailed, None))),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic peers never resolve or contact the public diagnostic destination.
    //! They check the bytes crossing each protocol boundary, not billing or bodies.

    use std::{future::Future, time::Duration};

    use rcgen::generate_simple_self_signed;
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
    use tokio::{io::DuplexStream, net::TcpListener, sync::oneshot};
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const USER: &str = "diagnostic-user-canary";
    const PASSWORD: &[u8] = b"diagnostic password:canary";

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("synthetic peer did not finish")
    }

    async fn head(stream: &mut (impl AsyncRead + Unpin + ?Sized)) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() == 16 * 1024 {
                return Err(io::Error::other("synthetic request exceeded limit"));
            }
            bytes.push(stream.read_u8().await?);
        }
        Ok(bytes)
    }

    async fn fragmented(stream: &mut (impl AsyncWrite + Unpin + ?Sized), bytes: &[u8]) {
        for chunk in bytes.chunks(3) {
            stream.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    fn connect_request(bytes: &[u8]) {
        let request = std::str::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("connect example.com:443 http/1.1\r\n"));
        assert!(request.contains("\r\nhost: example.com:443\r\n"));
        assert_eq!(request.matches("\r\nproxy-authorization:").count(), 1);
        let expected = authorization(USER, PASSWORD).unwrap();
        assert!(request.contains(&expected.to_str().unwrap().to_ascii_lowercase()));
    }

    async fn socks_auth(stream: &mut (impl Io + ?Sized)) {
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        fragmented(stream, &[5, 2]).await;
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, [1, u8::try_from(USER.len()).unwrap()]);
        let mut username = vec![0; USER.len()];
        stream.read_exact(&mut username).await.unwrap();
        assert!(username == USER.as_bytes(), "unexpected synthetic username");
        assert_eq!(usize::from(stream.read_u8().await.unwrap()), PASSWORD.len());
        let mut password = vec![0; PASSWORD.len()];
        stream.read_exact(&mut password).await.unwrap();
        assert!(password == PASSWORD, "unexpected synthetic password");
    }

    async fn socks_connect(stream: &mut (impl Io + ?Sized)) {
        fragmented(stream, &[1, 0]).await;
        let mut request = [0; 18];
        stream.read_exact(&mut request).await.unwrap();
        let mut expected = vec![5, 1, 0, 3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&443_u16.to_be_bytes());
        assert_eq!(request.as_slice(), expected);
    }

    #[tokio::test]
    async fn connect_any_success_ignores_body_framing_and_preserves_both_directions() {
        bounded(async {
        let (client, mut peer) = tokio::io::duplex(4096);
        let client = async {
            let mut stream = http_tunnel(Box::new(client), USER, PASSWORD).await.unwrap();
            let mut early = [0; 5];
            stream.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early");
            stream.write_all(b"outbound").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut tail = Vec::new();
            stream.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"after-half-close");
        };
        let server = async {
            connect_request(&head(&mut peer).await.unwrap());
            fragmented(&mut peer, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 999999\r\nTransfer-Encoding: chunked").await;
            peer.write_all(b"\r\n\r\nearly").await.unwrap();
            let mut outbound = Vec::new();
            peer.read_to_end(&mut outbound).await.unwrap();
            assert_eq!(outbound, b"outbound");
            peer.write_all(b"after-half-close").await.unwrap();
            peer.shutdown().await.unwrap();
        };
        tokio::join!(client, server);
    }).await;
    }

    #[tokio::test]
    async fn rejected_connect_closes_without_retry_or_following_location() {
        for (status, code) in [
            (407, Code::AuthenticationRejected),
            (302, Code::TunnelRejected),
        ] {
            bounded(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            let client = async {
                assert_eq!(http_tunnel(Box::new(client), USER, PASSWORD).await.err().unwrap(), (code, Some(status)));
            };
            let server = async {
                connect_request(&head(&mut peer).await.unwrap());
                peer.write_all(format!("HTTP/1.1 {status} synthetic\r\nLocation: https://forbidden.invalid/\r\nContent-Length: 1000\r\n\r\nremote-body-canary").as_bytes()).await.unwrap();
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            };
            tokio::join!(client, server);
        }).await;
        }
    }

    #[tokio::test]
    async fn socks_requires_offered_method_and_checks_authentication_once() {
        for (selection, expected) in [
            ([5, 0], Code::InvalidResponse),
            ([5, 255], Code::MethodRejected),
            ([4, 2], Code::InvalidResponse),
        ] {
            bounded(async {
                let (client, mut peer) = tokio::io::duplex(4096);
                let client = async {
                    assert_eq!(
                        socks_tunnel(Box::new(client), USER, PASSWORD)
                            .await
                            .err()
                            .unwrap(),
                        (expected, None)
                    );
                };
                let server = async {
                    let mut greeting = [0; 3];
                    peer.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 2]);
                    peer.write_all(&selection).await.unwrap();
                    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                };
                tokio::join!(client, server);
            })
            .await;
        }
        bounded(async {
            let (client, mut peer) = tokio::io::duplex(4096);
            let client = async {
                assert_eq!(
                    socks_tunnel(Box::new(client), USER, PASSWORD)
                        .await
                        .err()
                        .unwrap(),
                    (Code::AuthenticationRejected, Some(7))
                );
            };
            let server = async {
                socks_auth(&mut peer).await;
                fragmented(&mut peer, &[1, 7]).await;
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            };
            tokio::join!(client, server);
        })
        .await;
    }

    #[tokio::test]
    async fn socks_consumes_every_bound_address_without_losing_tunnel_bytes() {
        let mut ipv6 = vec![5, 0, 0, 4];
        ipv6.extend_from_slice(&[0; 16]);
        ipv6.extend_from_slice(&[0x12, 0x34]);
        for reply in [
            vec![5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34],
            vec![5, 0, 0, 3, 3, b'b', b'n', b'd', 0x12, 0x34],
            ipv6,
        ] {
            bounded(async {
                let (client, mut peer) = tokio::io::duplex(4096);
                let client = async {
                    let mut stream = socks_tunnel(Box::new(client), USER, PASSWORD)
                        .await
                        .unwrap();
                    let mut early = [0; 5];
                    stream.read_exact(&mut early).await.unwrap();
                    assert_eq!(&early, b"early");
                };
                let server = async {
                    socks_auth(&mut peer).await;
                    socks_connect(&mut peer).await;
                    // The last address fragment and first tunnel bytes share a write.
                    fragmented(&mut peer, &reply[..reply.len() - 2]).await;
                    let mut tail = reply[reply.len() - 2..].to_vec();
                    tail.extend_from_slice(b"early");
                    peer.write_all(&tail).await.unwrap();
                };
                tokio::join!(client, server);
            })
            .await;
        }
    }

    struct Identity {
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
        pem: String,
    }

    fn identity(names: &[&str]) -> Identity {
        let certified = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
                )
                .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        Identity {
            server: Arc::new(server),
            client: config(roots).unwrap(),
            pem: certified.cert.pem(),
        }
    }

    fn profile(protocol: Protocol, port: u16) -> Profile {
        serde_json::from_value(serde_json::json!({
            "format_version": 1, "protocol": protocol, "host": "127.0.0.1",
            "port": port, "username": USER, "operation": "connect",
        }))
        .unwrap()
    }

    async fn proxy_accept(stream: &mut (impl Io + ?Sized), protocol: Protocol) {
        if protocol == Protocol::Socks5 {
            socks_auth(stream).await;
            socks_connect(stream).await;
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
        } else {
            connect_request(&head(stream).await.unwrap());
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        }
    }

    fn redacted(report: &Report) -> serde_json::Value {
        let bytes = serde_json::to_string(report).unwrap();
        for canary in [
            USER,
            std::str::from_utf8(PASSWORD).unwrap(),
            "remote-body-canary",
            "forbidden.invalid",
        ] {
            assert!(
                !bytes.contains(canary),
                "report retained private peer/input text"
            );
        }
        serde_json::from_str(&bytes).unwrap()
    }

    #[tokio::test]
    async fn all_protocols_reach_fixed_tls_target_and_return_headers_without_body_or_eof() {
        let proxy = identity(&["127.0.0.1"]);
        let target = identity(&["example.com"]);
        for protocol in [Protocol::Http, Protocol::Https, Protocol::Socks5] {
            bounded(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let profile = profile(protocol, listener.local_addr().unwrap().port());
                let mut report = Report::new(protocol);
                let mut stage = Stage::ProxyTcp;
                let client = async {
                    execute(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        Trust {
                            proxy: proxy.client.clone(),
                            target: target.client.clone(),
                        },
                        &mut report,
                        &mut stage,
                    )
                    .await
                    .unwrap();
                };
                let server = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream: Stream = if protocol == Protocol::Https {
                        Box::new(
                            TlsAcceptor::from(proxy.server.clone())
                                .accept(stream)
                                .await
                                .unwrap(),
                        )
                    } else {
                        Box::new(stream)
                    };
                    proxy_accept(&mut *stream, protocol).await;
                    let mut origin = TlsAcceptor::from(target.server.clone())
                        .accept(stream)
                        .await
                        .unwrap();
                    let request = String::from_utf8(head(&mut origin).await.unwrap())
                        .unwrap()
                        .to_ascii_lowercase();
                    assert!(request.starts_with("get / http/1.1\r\n"));
                    assert!(request.contains("\r\nhost: example.com\r\n"));
                    assert!(!request.contains("authorization:"));
                    assert!(!request.contains(USER));
                    origin
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nremote-body-canary",
                        )
                        .await
                        .unwrap();
                    origin.flush().await.unwrap();
                    // Keep the response incomplete: returning must depend on headers,
                    // not a complete body, TLS close_notify or the peer's EOF.
                    assert!(matches!(origin.read(&mut [0]).await, Ok(0) | Err(_)));
                };
                tokio::join!(client, server);
                report.success = true;
                let value = redacted(&report);
                assert_eq!(value["steps"][4]["outcome"], "passed");
                assert_eq!(value["steps"][4]["status"], 200);
                assert!(
                    value["unchecked"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value == "response_body")
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn outer_ca_and_name_validation_cannot_authorize_the_target() {
        let shared = identity(&["127.0.0.1", "example.com"]);
        let target = identity(&["example.com"]);
        let wrong_name = identity(&["wrong.invalid"]);
        // First fail before sending credentials; then reject an origin signed by
        // the trusted proxy identity; finally reject a trusted origin's wrong SAN.
        for case in 0..3 {
            bounded(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let profile = profile(Protocol::Https, listener.local_addr().unwrap().port());
                let outer = if case == 0 { &wrong_name } else { &shared };
                let inner = if case == 1 { &shared } else { &wrong_name };
                let mut report = Report::new(Protocol::Https);
                let mut stage = Stage::ProxyTcp;
                let client = async {
                    let result = execute(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        Trust {
                            proxy: outer.client.clone(),
                            target: if case == 2 {
                                wrong_name.client.clone()
                            } else {
                                target.client.clone()
                            },
                        },
                        &mut report,
                        &mut stage,
                    )
                    .await;
                    assert_eq!(result, Err((Code::TlsFailed, None)));
                };
                let server = async {
                    let (stream, _) = listener.accept().await.unwrap();
                    let outer = TlsAcceptor::from(outer.server.clone()).accept(stream).await;
                    if case == 0 {
                        assert!(outer.is_err());
                        return;
                    }
                    let mut outer = outer.unwrap();
                    proxy_accept(&mut outer, Protocol::Https).await;
                    assert!(
                        TlsAcceptor::from(inner.server.clone())
                            .accept(outer)
                            .await
                            .is_err()
                    );
                };
                tokio::join!(client, server);
                assert!(matches!(
                    (case, stage),
                    (0, Stage::ProxyTls) | (1 | 2, Stage::TargetTls)
                ));
                report.fail(stage, Code::TlsFailed, None);
                redacted(&report);
            })
            .await;
        }
    }

    #[tokio::test]
    async fn loading_a_proxy_ca_keeps_the_real_target_root_store_independent() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("proxy-ca.pem"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-test-proxy-ca-{:032x}",
            u128::from_be_bytes(random)
        )));
        crate::manage::files::create_directory(&fixture.0).unwrap();
        let shared = identity(&["127.0.0.1", "example.com"]);
        crate::manage::files::write(&fixture.0, "proxy-ca.pem", shared.pem.as_bytes()).unwrap();
        // Use the production factory, not a hand-built Trust. If it accidentally
        // adds this public test certificate to target roots, the inner TLS would
        // succeed and wait for a GET instead of failing at TargetTls.
        let trust = Trust::load(Some(&fixture.0.join("proxy-ca.pem"))).unwrap();
        bounded(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let profile = profile(Protocol::Https, listener.local_addr().unwrap().port());
            let mut report = Report::new(Protocol::Https);
            let mut stage = Stage::ProxyTcp;
            let client = async {
                assert_eq!(
                    execute(
                        &profile,
                        profile.server_name().unwrap(),
                        PASSWORD,
                        trust,
                        &mut report,
                        &mut stage
                    )
                    .await,
                    Err((Code::TlsFailed, None))
                );
            };
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut outer = TlsAcceptor::from(shared.server.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                proxy_accept(&mut outer, Protocol::Https).await;
                assert!(
                    TlsAcceptor::from(shared.server.clone())
                        .accept(outer)
                        .await
                        .is_err()
                );
            };
            tokio::join!(client, server);
            assert!(matches!(stage, Stage::TargetTls));
            report.fail(stage, Code::TlsFailed, None);
            let value = redacted(&report);
            assert_eq!(value["steps"][1]["outcome"], "passed");
            assert_eq!(value["steps"][2]["outcome"], "passed");
            assert_eq!(value["steps"][3]["code"], "tls_failed");
        })
        .await;
    }

    #[tokio::test]
    async fn target_redirect_is_reported_without_following_or_waiting_for_body() {
        bounded(async {
        let (client, mut peer) = tokio::io::duplex(4096);
        let client = async {
            assert_eq!(target_response(Box::new(client)).await, Err((Code::RedirectNotFollowed, Some(302))));
        };
        let server = async {
            let request = head(&mut peer).await.unwrap();
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            peer.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://forbidden.invalid/\r\nContent-Length: 1000\r\n\r\nremote-body-canary").await.unwrap();
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        };
        tokio::join!(client, server);
    }).await;
    }

    #[tokio::test]
    async fn timeout_and_explicit_cancellation_drop_the_single_owned_http_driver() {
        for cancel in [false, true] {
            bounded(async {
                let (client, mut peer): (DuplexStream, DuplexStream) = tokio::io::duplex(4096);
                let (accepted, observed) = oneshot::channel();
                let client = async {
                    let exchange = http_tunnel(Box::new(client), USER, PASSWORD);
                    tokio::pin!(exchange);
                    tokio::select! {
                        result = observed => result.unwrap(),
                        _ = &mut exchange => panic!("stalled proxy unexpectedly answered"),
                    }
                    if !cancel {
                        assert!(
                            tokio::time::timeout(Duration::from_millis(50), &mut exchange)
                                .await
                                .is_err()
                        );
                    }
                    // Explicit cancellation drops the still-pending future here;
                    // timeout above must drop the same driver and socket as well.
                };
                let server = async {
                    connect_request(&head(&mut peer).await.unwrap());
                    accepted.send(()).unwrap();
                    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                };
                tokio::join!(client, server);
            })
            .await;
        }
    }
}
