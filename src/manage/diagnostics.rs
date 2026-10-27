//! Allowlisted offline diagnostics, separate from identity-bearing status output.
//!
//! Collection never starts a runtime, probes a listener, takes a service lock or
//! scans logs/configuration. Only explicitly selected public node certificates
//! are checked; no TLS private key or automation header is loaded.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use serde::Serialize;

use super::{
    store::diagnostics::{
        self as storage, Check, Code, Component, EXPECTED_SCHEMA_VERSION, Inspection, Status,
    },
    tls,
};

/// Explicit paths are inputs only; they are never included in report/error data.
#[derive(clap::Args)]
pub struct Args {
    /// Existing persistent management directory; never initialized or migrated
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Optional PEM CA bundle for the separate node-certificate profile check
    #[arg(long, requires_all = ["node_certificate", "node_name"])]
    node_ca: Option<PathBuf>,
    /// Leaf-first public PEM node chain; no private key is read
    #[arg(long, requires_all = ["node_ca", "node_name"])]
    node_certificate: Option<PathBuf>,
    /// Expected node SAN; not a URL or proof of control authorization
    #[arg(long, requires_all = ["node_ca", "node_certificate"])]
    node_name: Option<String>,
}

/// Stable report envelope; dynamic identities, paths and error text have no field.
#[derive(Serialize)]
struct Report {
    format_version: u8,
    scope: &'static str,
    vproxy_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    features: Features,
    sqlite_version: &'static str,
    expected_schema: u32,
    observed_schema: Option<u32>,
    checks_passed: bool,
    checks: Vec<Check>,
    limitations: [&'static str; 8],
}

/// Compile-time capabilities are not observations of running services or eBPF.
#[derive(Serialize)]
struct Features {
    management: bool,
    embedded_web: bool,
    ebpf_compiled: bool,
}

/// Write one complete collected report, then fail if a check needs attention.
///
/// SQLite uses its ordinary read-only WAL behavior, not immutable/forensic mode;
/// sidecars may be accessed or created. Its busy timeout bounds lock waits, not
/// all I/O/SQL execution. No local or remote repair is attempted on any result.
pub(super) fn run(args: Args) -> io::Result<()> {
    let report = collect(&args);
    write_report(&mut io::stdout().lock(), &report)?;
    if report.checks_passed {
        Ok(())
    } else {
        Err(io::Error::other(
            "offline diagnostic checks need attention; inspect the JSON report",
        ))
    }
}

/// Keep certificate checking independent of storage failures, while exposing
/// only fixed result enums from either path; neither input path is retained.
fn collect(args: &Args) -> Report {
    let (resolution, mut inspection) = match super::directory(args.data_dir.clone()) {
        Ok(directory) => (
            Check {
                component: Component::DirectoryResolution,
                status: Status::Passed,
                code: Code::Checked,
            },
            storage::inspect(&directory),
        ),
        Err(error) => (
            Check {
                component: Component::DirectoryResolution,
                status: Status::Failed,
                code: match error.kind() {
                    io::ErrorKind::InvalidInput => Code::InvalidPath,
                    io::ErrorKind::NotFound => Code::Missing,
                    io::ErrorKind::PermissionDenied => Code::PermissionDenied,
                    _ => Code::IoFailure,
                },
            },
            Inspection {
                observed_schema: None,
                expected_schema: EXPECTED_SCHEMA_VERSION,
                checks: Vec::new(),
            },
        ),
    };
    inspection.checks.insert(0, resolution);
    inspection.checks.push(node_certificate(args));
    let checks_passed = inspection
        .checks
        .iter()
        .all(|check| matches!(check.status, Status::Passed | Status::NotChecked));
    Report {
        format_version: 1,
        scope: "offline_configuration",
        vproxy_version: env!("CARGO_PKG_VERSION"),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        features: Features {
            management: true,
            embedded_web: cfg!(feature = "web-ui"),
            ebpf_compiled: cfg!(all(target_os = "linux", feature = "ebpf")),
        },
        sqlite_version: rusqlite::version(),
        expected_schema: inspection.expected_schema,
        observed_schema: inspection.observed_schema,
        checks_passed,
        checks: inspection.checks,
        limitations: [
            "service_runtime_and_network_not_checked",
            "private_keys_and_key_possession_not_checked",
            "node_authorization_not_checked",
            "not_a_database_integrity_scan",
            "sqlite_wal_sidecar_access_possible",
            "no_total_execution_deadline",
            "trusted_ancestor_directories_required",
            if cfg!(unix) {
                "unix_mode_bits_only_not_an_acl_audit"
            } else {
                "filesystem_acl_not_checked"
            },
        ],
    }
}

/// Check only the explicitly requested public node profile: chain, time, both
/// TLS usages and expected SAN. It cannot prove private-key possession, browser
/// trust, remote reachability, peer enrollment or policy-owner authorization.
fn node_certificate(args: &Args) -> Check {
    let (status, code) = match (&args.node_ca, &args.node_certificate, &args.node_name) {
        (None, None, None) => (Status::NotChecked, Code::NotRequested),
        (Some(ca), Some(certificate), Some(name)) => {
            match tls::load_peer_certificate(ca, certificate, name) {
                Ok(_) => (Status::Passed, Code::Checked),
                Err(error) => (
                    Status::Failed,
                    match error.kind() {
                        io::ErrorKind::NotFound => Code::Missing,
                        io::ErrorKind::PermissionDenied => Code::PermissionDenied,
                        io::ErrorKind::InvalidInput => Code::InvalidArguments,
                        io::ErrorKind::InvalidData => Code::InvalidCertificate,
                        _ => Code::IoFailure,
                    },
                ),
            }
        }
        _ => (Status::Failed, Code::InvalidArguments),
    };
    Check {
        component: Component::NodeCertificate,
        status,
        code,
    }
}

/// Serialize before the first write; a broken stdout still returns a fixed
/// diagnostic and cannot expose a caller's writer error or its embedded paths.
fn write_report(output: &mut impl Write, report: &Report) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|_| io::Error::other("cannot encode offline diagnostic report"))?;
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .map_err(|error| io::Error::new(error.kind(), "cannot write offline diagnostic report"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, DirBuilder, OpenOptions},
        path::Path,
    };

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use serde_json::Value;

    use super::*;
    use crate::manage::store;

    const PATH_CANARY: &str = "diagnostic-private-path-canary";
    const NODE_CANARY: &str = "diagnostic-private-node-canary";
    const ADMIN_CANARY: &str = "diagnostic-private-admin-canary";
    const PHC_CANARY: &str = "diagnostic-private-phc-canary";
    const CA_CANARY: &str = "diagnostic-private-ca-canary";
    const SAN_CANARY: &str = "diagnostic-private-san-canary.invalid";

    /// Each fixture owns an exclusively created directory, never a runtime path.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let path = std::env::temp_dir().join(format!(
                "vproxy-{PATH_CANARY}-{:032x}",
                u128::from_be_bytes(random)
            ));
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path)?;
            Ok(Self(path))
        }

        fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            let path = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(bytes)?;
            Ok(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(directory: &Path) -> Args {
        Args {
            data_dir: Some(directory.to_owned()),
            node_ca: None,
            node_certificate: None,
            node_name: None,
        }
    }

    fn rendered(report: &Report) -> io::Result<(String, Value)> {
        let mut output = Vec::new();
        write_report(&mut output, report)?;
        assert!(output.ends_with(b"\n"));
        let value = serde_json::from_slice(&output).map_err(io::Error::other)?;
        let text = String::from_utf8(output).map_err(io::Error::other)?;
        Ok((text, value))
    }

    fn assert_keys(value: &Value, expected: &[&str]) {
        let mut actual: Vec<_> = value
            .as_object()
            .expect("diagnostic object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    fn check(report: &Report, component: Component) -> Check {
        let found: Vec<_> = report
            .checks
            .iter()
            .filter(|item| item.component == component)
            .copied()
            .collect();
        assert_eq!(found.len(), 1);
        found[0]
    }

    fn public_identity(fixture: &Fixture) -> io::Result<(PathBuf, PathBuf)> {
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.distinguished_name.push(DnType::CommonName, CA_CANARY);
        let issuer =
            CertifiedIssuer::self_signed(ca, KeyPair::generate().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        let mut leaf =
            CertificateParams::new(vec![SAN_CANARY.to_owned()]).map_err(io::Error::other)?;
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let certificate = leaf.signed_by(&key, &issuer).map_err(io::Error::other)?;
        // Neither key is written: the diagnostic accepts only public certificates.
        Ok((
            fixture.write("ca-path-canary.pem", issuer.pem().as_bytes())?,
            fixture.write("certificate-path-canary.pem", certificate.pem().as_bytes())?,
        ))
    }

    #[test]
    fn collected_metadata_is_projected_into_an_allowlisted_redacted_report() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let original = store::initialize(&fixture.0, NODE_CANARY, ADMIN_CANARY, PHC_CANARY)?;
        let report = collect(&args(&fixture.0));
        assert!(report.checks_passed);
        assert_eq!(report.observed_schema, Some(report.expected_schema));
        let (text, value) = rendered(&report)?;
        assert_keys(
            &value,
            &[
                "format_version",
                "scope",
                "vproxy_version",
                "operating_system",
                "architecture",
                "features",
                "sqlite_version",
                "expected_schema",
                "observed_schema",
                "checks_passed",
                "checks",
                "limitations",
            ],
        );
        assert_keys(
            &value["features"],
            &["management", "embedded_web", "ebpf_compiled"],
        );
        for item in value["checks"].as_array().expect("checks array") {
            assert_keys(item, &["component", "status", "code"]);
        }
        assert_eq!(value["format_version"], 1);
        assert_eq!(value["scope"], "offline_configuration");
        for canary in [
            PATH_CANARY,
            NODE_CANARY,
            ADMIN_CANARY,
            PHC_CANARY,
            &original.node_id,
        ] {
            assert!(!text.contains(canary), "report disclosed a fixture canary");
        }
        assert!(
            report
                .limitations
                .contains(&"service_runtime_and_network_not_checked")
        );
        assert!(report.limitations.contains(&if cfg!(unix) {
            "unix_mode_bits_only_not_an_acl_audit"
        } else {
            "filesystem_acl_not_checked"
        }));
        Ok(())
    }

    #[test]
    fn missing_and_empty_directory_inputs_fail_without_creating_any_state() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let missing = fixture.0.join("missing-path-canary");
        let report = collect(&args(&missing));
        assert!(!report.checks_passed);
        assert_eq!(check(&report, Component::Directory).code, Code::Missing);
        let (text, value) = rendered(&report)?;
        assert_eq!(value["checks_passed"], false);
        assert!(!text.contains(PATH_CANARY));
        assert!(!text.contains("missing-path-canary"));
        assert!(!missing.exists());
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);

        let report = collect(&args(Path::new("")));
        assert!(!report.checks_passed);
        assert_eq!(
            check(&report, Component::DirectoryResolution),
            Check {
                component: Component::DirectoryResolution,
                status: Status::Failed,
                code: Code::InvalidPath,
            }
        );
        assert!(report.observed_schema.is_none());
        let (_, value) = rendered(&report)?;
        assert_eq!(value["checks"][0]["code"], "invalid_path");
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);
        Ok(())
    }

    #[test]
    fn optional_certificate_arguments_are_not_silently_completed_or_downgraded() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let defaults = args(&fixture.0);
        assert_eq!(
            node_certificate(&defaults),
            Check {
                component: Component::NodeCertificate,
                status: Status::NotChecked,
                code: Code::NotRequested,
            }
        );
        for mask in 1..7 {
            let mut input = args(&fixture.0);
            input.node_ca = (mask & 1 != 0).then(|| fixture.0.join("unread-ca-path-canary"));
            input.node_certificate =
                (mask & 2 != 0).then(|| fixture.0.join("unread-cert-path-canary"));
            input.node_name = (mask & 4 != 0).then(|| SAN_CANARY.to_owned());
            assert_eq!(
                node_certificate(&input),
                Check {
                    component: Component::NodeCertificate,
                    status: Status::Failed,
                    code: Code::InvalidArguments,
                },
                "partial mask={mask}",
            );
        }
        assert_eq!(fs::read_dir(&fixture.0)?.count(), 0);
        Ok(())
    }

    #[test]
    fn valid_public_node_certificate_needs_no_key_file_and_leaks_no_ca_or_san() -> io::Result<()> {
        let fixture = Fixture::new()?;
        store::initialize(&fixture.0, NODE_CANARY, ADMIN_CANARY, PHC_CANARY)?;
        let (ca, certificate) = public_identity(&fixture)?;
        let mut input = args(&fixture.0);
        input.node_ca = Some(ca);
        input.node_certificate = Some(certificate);
        input.node_name = Some(SAN_CANARY.to_owned());
        let report = collect(&input);
        assert!(report.checks_passed);
        assert_eq!(
            check(&report, Component::NodeCertificate),
            Check {
                component: Component::NodeCertificate,
                status: Status::Passed,
                code: Code::Checked,
            }
        );
        let (text, _) = rendered(&report)?;
        for canary in [
            PATH_CANARY,
            NODE_CANARY,
            ADMIN_CANARY,
            PHC_CANARY,
            CA_CANARY,
            SAN_CANARY,
            "ca-path-canary.pem",
            "certificate-path-canary.pem",
            "-----BEGIN CERTIFICATE-----",
        ] {
            assert!(
                !text.contains(canary),
                "report disclosed certificate or stored metadata"
            );
        }
        assert!(
            report
                .limitations
                .contains(&"private_keys_and_key_possession_not_checked")
        );
        assert!(
            report
                .limitations
                .contains(&"node_authorization_not_checked")
        );
        Ok(())
    }

    #[test]
    fn certificate_failures_map_to_fixed_codes_without_echoing_the_selected_inputs()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let (ca, certificate) = public_identity(&fixture)?;
        let mut input = args(&fixture.0);
        input.node_ca = Some(ca);
        input.node_certificate = Some(certificate);
        for (name, expected) in [
            ("wrong-san-path-canary.invalid", Code::InvalidCertificate),
            ("invalid reference name canary", Code::InvalidArguments),
        ] {
            input.node_name = Some(name.to_owned());
            let result = node_certificate(&input);
            assert_eq!(result.status, Status::Failed);
            assert_eq!(result.code, expected);
            let encoded = serde_json::to_string(&result).map_err(io::Error::other)?;
            assert!(!encoded.contains(name));
            assert!(!encoded.contains(PATH_CANARY));
        }
        input.node_name = Some(SAN_CANARY.to_owned());
        input.node_ca = Some(fixture.0.join("missing-ca-path-canary.pem"));
        assert_eq!(node_certificate(&input).code, Code::Missing);
        input.node_ca = Some(fixture.0.join("ca-path-canary.pem"));
        input.node_certificate =
            Some(fixture.write("malformed-public-certificate.pem", b"PEM-PAYLOAD-CANARY")?);
        assert_eq!(node_certificate(&input).code, Code::InvalidCertificate);
        let (text, _) = rendered(&collect(&input))?;
        for canary in [
            PATH_CANARY,
            SAN_CANARY,
            "PEM-PAYLOAD-CANARY",
            "malformed-public-certificate.pem",
        ] {
            assert!(!text.contains(canary));
        }
        Ok(())
    }

    #[test]
    fn writer_errors_preserve_the_io_kind_but_not_the_original_error_text() -> io::Result<()> {
        struct FailingWriter {
            prefix: Vec<u8>,
            allowed: usize,
            kind: io::ErrorKind,
        }
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.prefix.len() == self.allowed {
                    return Err(io::Error::new(self.kind, "WRITER-PRIVATE-PATH-CANARY"));
                }
                let count = bytes.len().min(self.allowed - self.prefix.len());
                self.prefix.extend_from_slice(&bytes[..count]);
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let report = collect(&args(Path::new("")));
        for (allowed, kind) in [(0, io::ErrorKind::BrokenPipe), (8, io::ErrorKind::Other)] {
            let mut writer = FailingWriter {
                prefix: Vec::new(),
                allowed,
                kind,
            };
            let error = write_report(&mut writer, &report).expect_err("writer must fail");
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "cannot write offline diagnostic report");
            assert!(!error.to_string().contains("WRITER-PRIVATE-PATH-CANARY"));
            assert_eq!(writer.prefix.len(), allowed);
        }
        Ok(())
    }
}
