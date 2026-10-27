//! Explicit local proxy diagnostics, independent of management identities/state.
//!
//! The profile cannot choose a destination, HTTP header, local trust file or
//! command. Only the operator can supply a proxy CA and an existing password.
//! No retry, credential rotation, redirect or environment proxy is used.

mod profile;
mod transport;

use std::{
    io::{self, IsTerminal as _, Write as _},
    path::PathBuf,
    time::Duration,
};

use serde::Serialize;
use zeroize::Zeroizing;

use profile::{Profile, Protocol};

const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_HOST: &str = "example.com";
const TARGET_AUTHORITY: &str = "example.com:443";

/// One local client invocation. Profiles contain routing metadata, not passwords.
#[derive(clap::Args)]
pub struct Args {
    /// Non-secret connection profile exported from the connection preview
    #[arg(long)]
    profile: PathBuf,
    /// Explicit PEM roots for the HTTPS proxy only, never the target website
    #[arg(long)]
    proxy_ca: Option<PathBuf>,
    /// Read one existing proxy password from redirected stdin instead of a terminal
    #[arg(long)]
    password_stdin: bool,
    /// Consent to sending the proxy password without TLS (HTTP or SOCKS5)
    #[arg(long)]
    allow_plaintext: bool,
}

/// Fixed public stages. A passed tunnel does not imply successful target TLS.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    ProxyTcp,
    ProxyTls,
    ProxyTunnel,
    TargetTls,
    TargetHttp,
}

/// Outcomes deliberately contain no library error strings or remote text.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Code {
    TcpFailed,
    Timeout,
    Cancelled,
    CancellationUnavailable,
    TlsFailed,
    HttpFailed,
    IoFailed,
    AuthenticationRejected,
    TunnelRejected,
    MethodRejected,
    InvalidResponse,
    RedirectNotFollowed,
    TargetRejected,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    NotRun,
    NotApplicable,
    Passed,
    Failed,
}

/// A status code is the peer's numeric response, not its reason phrase or body.
#[derive(Serialize)]
struct Step {
    stage: Stage,
    outcome: Outcome,
    code: Option<Code>,
    status: Option<u16>,
}

/// Stable redacted JSON. Success proves one CONNECT and target response headers,
/// not body integrity, egress location, UDP, billing or continuity under restart.
#[derive(Serialize)]
struct Report {
    format_version: u8,
    protocol: Protocol,
    target: &'static str,
    success: bool,
    steps: [Step; 5],
    unchecked: [&'static str; 6],
}

impl Report {
    fn new(protocol: Protocol) -> Self {
        Self {
            format_version: 1,
            protocol,
            target: "https://example.com/",
            success: false,
            steps: [
                Stage::ProxyTcp,
                Stage::ProxyTls,
                Stage::ProxyTunnel,
                Stage::TargetTls,
                Stage::TargetHttp,
            ]
            .map(|stage| Step {
                stage,
                outcome: if matches!(stage, Stage::ProxyTls) && protocol != Protocol::Https {
                    Outcome::NotApplicable
                } else {
                    Outcome::NotRun
                },
                code: None,
                status: None,
            }),
            unchecked: [
                "socks5_bind",
                "socks5_udp",
                "masque",
                "egress_ip",
                "response_body",
                "billing_continuity",
            ],
        }
    }

    fn step(&mut self, stage: Stage) -> &mut Step {
        &mut self.steps[stage as usize]
    }

    fn pass(&mut self, stage: Stage, status: Option<u16>) {
        let step = self.step(stage);
        step.outcome = Outcome::Passed;
        step.status = status;
    }

    fn fail(&mut self, stage: Stage, code: Code, status: Option<u16>) {
        let step = self.step(stage);
        step.outcome = Outcome::Failed;
        step.code = Some(code);
        step.status = status;
    }
}

/// Validate all public input/trust before reading a secret or opening a socket.
/// The network deadline excludes synchronous file/terminal input; DNS may leave
/// an OS resolver job running after cancellation. No diagnostic starts a server.
pub(super) fn run(args: Args) -> io::Result<()> {
    let profile = Profile::read(&args.profile)?;
    if profile.protocol != Protocol::Https && !args.allow_plaintext {
        return Err(input(
            "HTTP/SOCKS5 sends the proxy password without TLS; explicitly use --allow-plaintext to continue",
        ));
    }
    if profile.protocol != Protocol::Https && args.proxy_ca.is_some() {
        return Err(input("--proxy-ca applies only to an HTTPS proxy"));
    }
    let trust = transport::Trust::load(args.proxy_ca.as_deref())?;
    let server_name = profile.server_name()?;
    writeln!(
        io::stderr().lock(),
        "Proxy: {:?} {}. Test destination: https://example.com/. Sends real traffic and may be metered. No retry or redirect.",
        profile.protocol,
        profile.authority(),
    )?;
    if profile.protocol != Protocol::Https {
        writeln!(
            io::stderr().lock(),
            "Warning: target HTTPS does not protect the password sent to this plaintext proxy."
        )?;
    }
    let password = if args.password_stdin {
        if io::stdin().is_terminal() {
            return Err(input("--password-stdin requires redirected input"));
        }
        read_password(io::stdin().lock())?
    } else {
        super::input::existing_password()?
    };
    validate_password(&password)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| io::Error::other("cannot start connection test runtime"))?;
    let mut report = Report::new(profile.protocol);
    let mut stage = Stage::ProxyTcp;
    let result = runtime.block_on(async {
        let result = tokio::time::timeout(
            TOTAL_TIMEOUT,
            transport::execute(
                &profile,
                server_name,
                &password,
                trust,
                &mut report,
                &mut stage,
            ),
        );
        tokio::pin!(result);
        tokio::select! {
            biased;
            cancelled = tokio::signal::ctrl_c() => Err((
                if cancelled.is_ok() { Code::Cancelled } else { Code::CancellationUnavailable },
                None,
            )),
            result = &mut result => result.unwrap_or(Err((Code::Timeout, None))),
        }
    });
    // Dropping the network future also drops both Hyper drivers and all sockets;
    // no detached connection task can keep sending credentials after this point.
    runtime.shutdown_timeout(Duration::from_millis(100));
    match result {
        Ok(()) => report.success = true,
        Err((code, status)) => report.fail(stage, code, status),
    }
    serde_json::to_writer_pretty(io::stdout().lock(), &report)
        .map_err(|_| io::Error::other("cannot write connection test report"))?;
    writeln!(io::stdout().lock())?;
    if report.success {
        Ok(())
    } else {
        Err(io::Error::other(
            "connection test failed; inspect the redacted report",
        ))
    }
}

/// Existing proxy passwords have no administrator creation minimum. Preserve
/// spaces and UTF-8 bytes; RFC 1929 bounds the length to one nonzero octet.
pub(super) fn validate_password(password: &[u8]) -> io::Result<()> {
    let valid =
        std::str::from_utf8(password).is_ok_and(|value| !value.chars().any(char::is_control));
    if password.is_empty() || password.len() > 255 || !valid {
        return Err(input(
            "proxy password must contain 1 to 255 UTF-8 bytes without control characters",
        ));
    }
    Ok(())
}

fn read_password(mut reader: impl io::Read) -> io::Result<Zeroizing<Vec<u8>>> {
    // A fixed buffer cannot reallocate and leave older secret copies behind.
    let mut bytes = Zeroizing::new([0_u8; 258]);
    let mut length = 0;
    loop {
        if length == bytes.len() {
            return Err(input("proxy password input is too long"));
        }
        let count = reader
            .read(&mut bytes[length..])
            .map_err(|_| input("cannot read proxy password"))?;
        if count == 0 {
            break;
        }
        length += count;
    }
    let mut password = &bytes[..length];
    if let Some(value) = password.strip_suffix(b"\n") {
        password = value.strip_suffix(b"\r").unwrap_or(value);
    }
    validate_password(password)?;
    Ok(Zeroizing::new(password.to_vec()))
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_password_accepts_short_and_preserves_spaces_and_colons() {
        for value in [b"a".as_slice(), b" : x: ", "短密码".as_bytes()] {
            let mut input = value.to_vec();
            input.extend_from_slice(b"\r\n");
            assert_eq!(read_password(input.as_slice()).unwrap().as_slice(), value);
        }
        assert_eq!(read_password([b'x'; 255].as_slice()).unwrap().len(), 255);
        for value in [
            b"".as_slice(),
            b"\n",
            b"x\ny",
            b"x\n\n",
            b"x\0",
            b"x\x7f",
            b"\xff",
            [b'x'; 256].as_slice(),
            [b'x'; 258].as_slice(),
        ] {
            assert!(read_password(value).is_err());
        }
    }

    #[test]
    fn report_preserves_partial_progress_without_credentials_or_remote_text() {
        let mut report = Report::new(Protocol::Http);
        report.pass(Stage::ProxyTcp, None);
        report.pass(Stage::ProxyTunnel, None);
        report.fail(Stage::TargetTls, Code::TlsFailed, None);
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["steps"][0]["outcome"], "passed");
        assert_eq!(value["steps"][1]["outcome"], "not_applicable");
        assert_eq!(value["steps"][2]["outcome"], "passed");
        assert_eq!(value["steps"][3]["code"], "tls_failed");
        assert_eq!(value["steps"][4]["outcome"], "not_run");
        assert_eq!(value["target"], "https://example.com/");
        assert!(
            value["unchecked"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("response_body"))
        );
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(!keys.contains(&"username"));
        assert!(!keys.contains(&"password"));
        assert!(!keys.contains(&"endpoint"));
    }

    #[test]
    fn plaintext_consent_and_ca_scope_fail_before_secret_input_or_network() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("profile.json"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-client-options-{:032x}",
            u128::from_be_bytes(random)
        )));
        std::fs::create_dir(&fixture.0).unwrap();
        let path = fixture.0.join("profile.json");
        // No listener/password/CA exists. These guards must precede every such read.
        for protocol in ["http", "socks5"] {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "format_version": 1, "protocol": protocol, "host": "127.0.0.1",
                    "port": 1, "username": "user", "operation": "connect",
                }))
                .unwrap(),
            )
            .unwrap();
            let args = |allow_plaintext| Args {
                profile: path.clone(),
                proxy_ca: Some(fixture.0.join("missing-ca.pem")),
                password_stdin: true,
                allow_plaintext,
            };
            assert!(
                run(args(false))
                    .unwrap_err()
                    .to_string()
                    .contains("--allow-plaintext")
            );
            assert_eq!(
                run(args(true)).unwrap_err().to_string(),
                "--proxy-ca applies only to an HTTPS proxy"
            );
        }
    }
}
