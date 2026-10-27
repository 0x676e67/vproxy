use std::{io, net::SocketAddr};

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

/// ACME is an explicit alternative for the browser HTTPS identity. Enabling it
/// requires a separate terms acknowledgement; node mTLS and proxy TLS are unchanged.
#[derive(Args, Default)]
pub struct Options {
    /// Automatically obtain and renew the browser HTTPS certificate
    #[arg(long)]
    acme: bool,
    /// Accept the selected CA's terms before account creation
    #[arg(long, requires = "acme")]
    acme_accept_terms: bool,
    /// Use Let's Encrypt production instead of its untrusted staging CA
    #[arg(long, requires = "acme")]
    acme_production: bool,
    /// Contact email (repeat at most four times)
    // The literal argv written into a plan separates flag/value. A valid email
    // local part can begin with '-', so serve must consume it as the value.
    #[arg(long, requires = "acme", allow_hyphen_values = true)]
    acme_contact: Vec<String>,
    /// Domain validation method; public TCP443 or TCP80 must reach this node
    #[arg(long, value_enum, default_value_t = Challenge::TlsAlpn01, requires = "acme")]
    acme_challenge: Challenge,
    /// Dedicated challenge-only HTTP bind, required with http-01
    #[arg(long, requires = "acme")]
    acme_http_bind: Option<SocketAddr>,
}

/// Validation endpoints are separate from the authenticated management router.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
pub(super) enum Challenge {
    #[default]
    #[value(name = "tls-alpn-01")]
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[value(name = "http-01")]
    #[serde(rename = "http-01")]
    Http01,
}

/// One fixed browser DNS name and CA. This is not a general ACME directory or
/// wildcard interface; callers cannot make the server contact arbitrary URLs.
#[derive(Clone)]
pub(super) struct Config {
    pub(super) domain: String,
    pub(super) directory: String,
    pub(super) production: bool,
    pub(super) contacts: Vec<String>,
    pub(super) challenge: Challenge,
    pub(super) http_bind: Option<SocketAddr>,
}

impl Config {
    /// Select an existing cache without issuance consent or I/O. Only the same
    /// canonical DNS origin and fixed CA choices accepted by serve are allowed;
    /// this scope alone does not authorize account creation or CA requests.
    pub(super) fn offline_scope(origin: &str, production: bool) -> io::Result<Self> {
        super::super::api::PublicOrigin::parse(origin)?;
        let origin = url::Url::parse(origin).map_err(|_| input("invalid ACME origin"))?;
        let Some(url::Host::Domain(domain)) = origin.host() else {
            return Err(input("ACME requires a DNS name, not an IP address"));
        };
        validate_domain(domain)?;
        Ok(Self {
            domain: domain.to_owned(),
            directory: if production {
                instant_acme::LetsEncrypt::Production
            } else {
                instant_acme::LetsEncrypt::Staging
            }
            .url()
            .to_owned(),
            production,
            contacts: Vec::new(),
            challenge: Challenge::TlsAlpn01,
            http_bind: None,
        })
    }
}

/// Immutable launch choices, not account/order state or a portable TLS identity.
/// Every field is explicit on disk; changing a choice requires a new plan.
/// Contacts remain raw emails, because the CLI adds mailto: itself.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct PlanOptions {
    enabled: bool,
    accept_terms: bool,
    production: bool,
    contacts: Vec<String>,
    challenge: Challenge,
    // A plain Option would silently accept an omitted field as None. The plan
    // records explicit null for TLS-ALPN, distinct from incomplete metadata.
    #[serde(deserialize_with = "Option::deserialize")]
    http_bind: Option<SocketAddr>,
}

impl Options {
    pub(in crate::manage) fn enabled(&self) -> bool {
        self.acme
    }

    /// Validate without reading a cache, binding a socket or contacting a CA.
    /// Disabled ACME returns no plan; enabled ACME requires the same explicit
    /// terms, DNS origin and challenge settings as manage serve.
    pub(in crate::manage) fn plan(&self, origin: &str) -> io::Result<Option<PlanOptions>> {
        Ok(self.configure(origin)?.map(|_| PlanOptions {
            enabled: self.acme,
            accept_terms: self.acme_accept_terms,
            production: self.acme_production,
            contacts: self.acme_contact.clone(),
            challenge: self.acme_challenge,
            http_bind: self.acme_http_bind,
        }))
    }

    pub(super) fn configure(&self, origin: &str) -> io::Result<Option<Config>> {
        if !self.acme {
            return Ok(None);
        }
        if !self.acme_accept_terms {
            return Err(input("ACME requires explicit --acme-accept-terms"));
        }
        let mut config = Config::offline_scope(origin, self.acme_production)?;
        if self.acme_contact.len() > 4 {
            return Err(input("ACME accepts at most four contact emails"));
        }
        let mut contacts = Vec::with_capacity(self.acme_contact.len());
        for contact in &self.acme_contact {
            if contact.len() > 254
                || !contact.is_ascii()
                || contact
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                || contact.contains([':', '?', '#', '/', '\\'])
                || contact.split('@').count() != 2
            {
                return Err(input("invalid ACME contact email"));
            }
            let (local, host) = contact
                .split_once('@')
                .ok_or_else(|| input("invalid ACME contact email"))?;
            if local.is_empty() || local.len() > 64 {
                return Err(input("invalid ACME contact email"));
            }
            validate_domain(host)?;
            let value = format!("mailto:{contact}");
            if !contacts.contains(&value) {
                contacts.push(value);
            }
        }
        let http_bind = match (self.acme_challenge, self.acme_http_bind) {
            (Challenge::Http01, Some(bind)) if bind.port() != 0 => Some(bind),
            (Challenge::TlsAlpn01, None) => None,
            _ => {
                return Err(input(
                    "http-01 requires --acme-http-bind; tls-alpn-01 must omit it",
                ));
            }
        };
        config.contacts = contacts;
        config.challenge = self.acme_challenge;
        config.http_bind = http_bind;
        Ok(Some(config))
    }
}

impl PlanOptions {
    /// Restore the exact CLI choices without validating them or performing I/O.
    /// The normal configure/prepare entry points remain responsible for consent,
    /// DNS/challenge checks and any runtime cache access.
    pub(in crate::manage) fn options(&self) -> Options {
        Options {
            acme: self.enabled,
            acme_accept_terms: self.accept_terms,
            acme_production: self.production,
            acme_contact: self.contacts.clone(),
            acme_challenge: self.challenge,
            acme_http_bind: self.http_bind,
        }
    }

    /// Revalidate the serialized choices and emit distinct literal CLI arguments.
    /// A missing first leaf is not an error: actual cache validation and issuance
    /// belong to serve, after its process-author and listener gates.
    pub(in crate::manage) fn arguments(&self, origin: &str) -> io::Result<Vec<String>> {
        self.options()
            .configure(origin)?
            .ok_or_else(|| input("an ACME launch plan must explicitly enable ACME"))?;
        let mut arguments = vec!["--acme".to_owned(), "--acme-accept-terms".to_owned()];
        if self.production {
            arguments.push("--acme-production".to_owned());
        }
        for contact in &self.contacts {
            arguments.extend(["--acme-contact".to_owned(), contact.clone()]);
        }
        arguments.extend([
            "--acme-challenge".to_owned(),
            match self.challenge {
                Challenge::TlsAlpn01 => "tls-alpn-01",
                Challenge::Http01 => "http-01",
            }
            .to_owned(),
        ]);
        if let Some(bind) = self.http_bind {
            arguments.extend(["--acme-http-bind".to_owned(), bind.to_string()]);
        }
        Ok(arguments)
    }

    pub(in crate::manage) fn http_bind(&self) -> Option<SocketAddr> {
        self.http_bind
    }
}

/// Accept canonical ASCII DNS identifiers with at least two labels. Wildcards,
/// trailing dots and IP literals need different validation and are not inferred.
fn validate_domain(domain: &str) -> io::Result<()> {
    if domain.len() > 253
        || !domain.contains('.')
        || !domain.is_ascii()
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(input("ACME requires an explicit non-wildcard DNS name"));
    }
    Ok(())
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_wire_and_cli_preserve_challenge_environment_and_raw_contacts() -> io::Result<()> {
        let origin = "https://admin.example.com";
        let bind: SocketAddr = "127.0.0.1:18080".parse().map_err(io::Error::other)?;
        for (challenge, challenge_name, production, http_bind) in [
            (Challenge::TlsAlpn01, "tls-alpn-01", false, None),
            (Challenge::Http01, "http-01", true, Some(bind)),
        ] {
            let options = Options {
                acme: true,
                acme_accept_terms: true,
                acme_production: production,
                acme_contact: vec!["--operator@example.com".to_owned()],
                acme_challenge: challenge,
                acme_http_bind: http_bind,
            };
            let plan = options
                .plan(origin)?
                .ok_or_else(|| input("missing ACME plan"))?;
            let wire = serde_json::to_value(&plan).map_err(io::Error::other)?;
            assert_eq!(
                wire,
                serde_json::json!({
                    "enabled": true,
                    "accept_terms": true,
                    "production": production,
                    "contacts": ["--operator@example.com"],
                    "challenge": challenge_name,
                    "http_bind": http_bind,
                })
            );
            let mut incomplete = wire.clone();
            incomplete
                .as_object_mut()
                .ok_or_else(|| input("ACME plan wire is not an object"))?
                .remove("http_bind");
            assert!(serde_json::from_value::<PlanOptions>(incomplete).is_err());
            // The TLS-ALPN case has explicit null; it must remain deserializable.
            let restored: PlanOptions = serde_json::from_value(wire).map_err(io::Error::other)?;
            let mut expected = vec!["--acme".to_owned(), "--acme-accept-terms".to_owned()];
            if production {
                expected.push("--acme-production".to_owned());
            }
            expected.extend([
                "--acme-contact".to_owned(),
                "--operator@example.com".to_owned(),
                "--acme-challenge".to_owned(),
                challenge_name.to_owned(),
            ]);
            if let Some(bind) = http_bind {
                expected.extend(["--acme-http-bind".to_owned(), bind.to_string()]);
            }
            assert_eq!(restored.arguments(origin)?, expected);
            let configured = restored
                .options()
                .configure(origin)?
                .ok_or_else(|| input("missing restored config"))?;
            assert_eq!(configured.contacts, ["mailto:--operator@example.com"]);
            assert_eq!(configured.production, production);
            assert_eq!(configured.challenge, challenge);
            assert_eq!(configured.http_bind, http_bind);
        }
        Ok(())
    }

    #[test]
    fn explicit_terms_domain_and_validation_listener_are_required() -> io::Result<()> {
        let mut options = Options {
            acme: true,
            ..Options::default()
        };
        assert!(options.configure("https://admin.example.com").is_err());
        options.acme_accept_terms = true;
        assert!(options.configure("https://127.0.0.1").is_err());
        assert!(options.configure("https://localhost").is_err());
        let config = options
            .configure("https://admin.example.com")?
            .ok_or_else(|| input("missing config"))?;
        assert_eq!(config.domain, "admin.example.com");
        assert_eq!(config.directory, instant_acme::LetsEncrypt::Staging.url());
        options.acme_challenge = Challenge::Http01;
        assert!(options.configure("https://admin.example.com").is_err());
        options.acme_http_bind = Some("127.0.0.1:8080".parse().map_err(io::Error::other)?);
        assert!(options.configure("https://admin.example.com")?.is_some());
        options.acme_challenge = Challenge::TlsAlpn01;
        assert!(options.configure("https://admin.example.com").is_err());
        Ok(())
    }
}
