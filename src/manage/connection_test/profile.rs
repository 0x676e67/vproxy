//! A bounded, non-secret connection description. It selects only the proxy;
//! the diagnostic's target and operation are not supplied by an imported file.

use std::{io, net::IpAddr, path::Path};

use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};

const MAX_PROFILE_BYTES: usize = 16 * 1024;

/// Client protocols supported by the fixed CONNECT diagnostic, not every
/// protocol or operation implemented by a vproxy listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase", try_from = "String")]
pub(super) enum Protocol {
    Http,
    Https,
    Socks5,
}

impl TryFrom<String> for Protocol {
    type Error = io::Error;

    fn try_from(value: String) -> io::Result<Self> {
        match value.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "socks5" => Ok(Self::Socks5),
            _ => Err(invalid()),
        }
    }
}

/// A single fixed operation keeps imported profiles from selecting a target,
/// HTTP method, local file or other client behavior.
#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(super) enum Operation {
    Connect,
}

impl TryFrom<String> for Operation {
    type Error = io::Error;

    fn try_from(value: String) -> io::Result<Self> {
        match value.as_str() {
            "connect" => Ok(Self::Connect),
            _ => Err(invalid()),
        }
    }
}

/// Public endpoint and full extension username, without a password. Do not add
/// `Debug`: callers should print only the selected protocol and authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub(super) format_version: u8,
    pub(super) protocol: Protocol,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) username: String,
    pub(super) operation: Operation,
}

impl Profile {
    /// Read one bounded regular file without changing its permissions. Neither
    /// filesystem paths nor JSON/library error text are retained in failures.
    pub(super) fn read(path: &Path) -> io::Result<Self> {
        let bytes = super::super::files::read(path, MAX_PROFILE_BYTES, false).map_err(|error| {
            io::Error::new(error.kind(), "connection profile could not be read")
        })?;
        let profile: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validate the whole profile before loading credentials or opening a
    /// socket. Usernames are ASCII and unambiguous in both Basic and SOCKS5.
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.format_version != 1
            || self.port == 0
            || self.username.is_empty()
            || self.username.len() > 1024
            || self.protocol == Protocol::Socks5 && self.username.len() > 255
            || !self.username.is_ascii()
            || self
                .username
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b':')
        {
            return Err(invalid());
        }
        let Operation::Connect = self.operation;
        self.server_name()?;
        Ok(())
    }

    /// Return the exact IP/DNS identity for normal TLS verification. Input is
    /// canonical ASCII without brackets or URL components; no DNS lookup runs.
    pub(super) fn server_name(&self) -> io::Result<ServerName<'static>> {
        if let Ok(address) = self.host.parse::<IpAddr>() {
            if self.host != address.to_string() {
                return Err(invalid());
            }
            return Ok(ServerName::IpAddress(address.into()));
        }
        if self.host.len() > 253
            || !self.host.is_ascii()
            || !self.host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && (label.as_bytes()[0].is_ascii_lowercase()
                        || label.as_bytes()[0].is_ascii_digit())
                    && (label.as_bytes()[label.len() - 1].is_ascii_lowercase()
                        || label.as_bytes()[label.len() - 1].is_ascii_digit())
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || !matches!(url::Host::parse(&self.host), Ok(url::Host::Domain(host)) if host == self.host)
        {
            return Err(invalid());
        }
        match ServerName::try_from(self.host.clone()).map_err(|_| invalid())? {
            name @ ServerName::DnsName(_) => Ok(name),
            _ => Err(invalid()),
        }
    }

    /// Format an already validated endpoint, adding IPv6 brackets only here.
    pub(super) fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid connection profile")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    fn profile(protocol: Protocol, host: &str, username: &str) -> Profile {
        Profile {
            format_version: 1,
            protocol,
            host: host.to_owned(),
            port: 1080,
            username: username.to_owned(),
            operation: Operation::Connect,
        }
    }

    fn document() -> serde_json::Value {
        serde_json::json!({
            "format_version": 1,
            "protocol": "https",
            "host": "proxy.example",
            "port": 443,
            "username": "user_region-us_session-1_device-linux",
            "operation": "connect"
        })
    }

    fn decode(value: serde_json::Value) -> io::Result<Profile> {
        let profile: Profile = serde_json::from_value(value).map_err(|_| invalid())?;
        profile.validate()?;
        Ok(profile)
    }

    #[test]
    fn canonical_endpoints_and_extension_usernames_are_preserved() {
        for protocol in [Protocol::Http, Protocol::Https, Protocol::Socks5] {
            for (host, authority) in [
                ("proxy.example", "proxy.example:1080"),
                ("localhost", "localhost:1080"),
                ("127.0.0.1", "127.0.0.1:1080"),
                ("2001:db8::1", "[2001:db8::1]:1080"),
            ] {
                let profile = profile(protocol, host, "user_region-us_session-1_device-linux");
                profile.validate().unwrap();
                assert_eq!(profile.authority(), authority);
                assert!(profile.server_name().is_ok());
                assert_eq!(profile.username, "user_region-us_session-1_device-linux");
            }
        }
        assert!(decode(document()).is_ok());
    }

    #[test]
    fn imported_shape_is_exact_and_cannot_add_secrets_or_operations() {
        for (key, value) in [
            ("password", serde_json::json!("secret-canary")),
            ("target", serde_json::json!("https://other.example/")),
            (
                "headers",
                serde_json::json!({"Authorization": "secret-canary"}),
            ),
            ("format_version", serde_json::json!(2)),
            ("format_version", serde_json::json!("1")),
            ("protocol", serde_json::json!("masque")),
            ("protocol", serde_json::json!("HTTPS")),
            ("protocol", serde_json::json!({"http": null})),
            ("operation", serde_json::json!("bind")),
            ("operation", serde_json::json!({"connect": {}})),
            ("operation", serde_json::json!({"connect": null})),
            ("port", serde_json::json!(0)),
            ("port", serde_json::json!(65536)),
            ("port", serde_json::json!("443")),
        ] {
            let mut value_with_change = document();
            value_with_change[key] = value;
            assert_eq!(
                decode(value_with_change).err().unwrap().to_string(),
                "invalid connection profile"
            );
        }
        for key in [
            "format_version",
            "protocol",
            "host",
            "port",
            "username",
            "operation",
        ] {
            let mut value = document();
            value.as_object_mut().unwrap().remove(key);
            assert!(decode(value).is_err());
        }
        let duplicate = br#"{"format_version":1,"protocol":"http","host":"localhost","port":80,"username":"a","username":"b","operation":"connect"}"#;
        assert!(serde_json::from_slice::<Profile>(duplicate).is_err());
    }

    #[test]
    fn hostname_and_username_bounds_reject_ambiguous_destinations() {
        for host in [
            "",
            "Proxy.example",
            "proxy.example.",
            "-proxy.example",
            "proxy-.example",
            "proxy..example",
            "proxy_name",
            "例子.example",
            "user@proxy.example",
            "proxy.example:443",
            "proxy.example/path",
            "proxy.example\\path",
            "proxy%2eexample",
            " proxy.example",
            "proxy.example\n",
            "[::1]",
            "2001:0db8::1",
            "2001:DB8::1",
            "fe80::1%1",
            "127.1",
            "0177.0.0.1",
            "0x7f000001",
            "2130706433",
        ] {
            assert!(
                profile(Protocol::Http, host, "user").validate().is_err(),
                "{host:?}"
            );
        }
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), 253);
        assert!(profile(Protocol::Http, &longest, "user").validate().is_ok());
        assert!(
            profile(Protocol::Http, &format!("a.{longest}"), "user")
                .validate()
                .is_err()
        );
        for username in [
            "",
            "user:name",
            "user name",
            "user\tname",
            "user\u{7f}",
            "用户",
            "user\u{a0}",
        ] {
            assert!(
                profile(Protocol::Http, "localhost", username)
                    .validate()
                    .is_err()
            );
        }
        assert!(
            profile(Protocol::Http, "localhost", &"x".repeat(1024))
                .validate()
                .is_ok()
        );
        assert!(
            profile(Protocol::Https, "localhost", &"x".repeat(1025))
                .validate()
                .is_err()
        );
        assert!(
            profile(Protocol::Socks5, "localhost", &"x".repeat(255))
                .validate()
                .is_ok()
        );
        assert!(
            profile(Protocol::Socks5, "localhost", &"x".repeat(256))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn file_reads_are_bounded_and_errors_do_not_retain_paths_or_input() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0.join("profile.json"));
                let _ = fs::remove_dir(&self.0);
            }
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "vproxy-profile-{:032x}",
            u128::from_be_bytes(random)
        )));
        fs::create_dir(&fixture.0).unwrap();
        let path = fixture.0.join("profile.json");
        fs::write(&path, serde_json::to_vec(&document()).unwrap()).unwrap();
        assert!(Profile::read(&path).is_ok());
        let mut oversized = serde_json::to_vec(&document()).unwrap();
        oversized.resize(MAX_PROFILE_BYTES + 1, b' ');
        fs::write(&path, oversized).unwrap();
        assert_eq!(
            Profile::read(&path).err().unwrap().to_string(),
            "connection profile could not be read"
        );
        fs::write(
            &path,
            br#"{"username":"secret-canary","password":"secret-canary"}"#,
        )
        .unwrap();
        assert_eq!(
            Profile::read(&path).err().unwrap().to_string(),
            "invalid connection profile"
        );
        let error = Profile::read(&fixture.0.join("secret-canary.json"))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "connection profile could not be read");
    }
}
