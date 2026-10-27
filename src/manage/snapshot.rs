//! Offline retained-identity packages. The database is persistently quarantined
//! before keys are written, and no command here can finalize or start it. An
//! integrity check is neither authenticated provenance nor a freshness witness.

pub(super) mod config;
pub(in crate::manage) mod inputs;
#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Fixed Source runtime admission remains fenced until writer, dependency and fencing gates are complete"
    )
)]
mod source;
#[cfg(feature = "witness-journal")]
pub(in crate::manage) use source::Registered;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use self::config::{Configuration, Tls};
use super::{acme, files, store, tls};

const MAX_MANIFEST: usize = 64 * 1024;
const MAX_ASSET: usize = 256 * 1024;
const MAX_ASSETS: usize = 176;
const MAX_TOTAL: usize = 40 * 1024 * 1024;
const MANIFEST: &str = "manifest.json";

/// Offline artifact operations. No branch constructs a server or issuer.
#[derive(Subcommand)]
pub enum Command {
    /// Export a checked launch plan as an editable private snapshot description
    Configure {
        #[arg(long)]
        plan: PathBuf,
        /// Explicit intended installation, not inferred from this executable
        #[arg(long, value_enum)]
        surface: config::Surface,
        /// New private directory; configuration.json never overwrites an input
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture the declared configuration and identities into a new inert package
    Create {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Private versioned startup description; this is not inferred from a process
        #[arg(long)]
        config: PathBuf,
        /// New private directory outside the source; failed output is never reused
        #[arg(long)]
        output: PathBuf,
    },
    /// Check private package integrity and archived static identities; never activates it
    Verify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Finish or reconcile the original witnessed seal of this prepared package
    Seal {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Existing private package; no source request or snapshot is recreated
        #[arg(long)]
        input: PathBuf,
    },
}

/// Private completion metadata; paths are fixed portable package references.
/// The manifest is unkeyed and cannot attest who created it or authorize replay.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u8,
    platform: String,
    snapshot_id: String,
    configuration_source: String,
    database: store::BackupManifest,
    configuration: Configuration,
    #[serde(deserialize_with = "Option::deserialize")]
    acme_cache: Option<acme::backup::Metadata>,
    assets: Vec<Asset>,
}

/// Whole-file integrity, not a credential verifier or a permission token. Even
/// public certificates/configuration receive private output permissions.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    name: String,
    bytes: usize,
    sha256: String,
}

/// Secret bytes never derive Debug/Serialize and zeroize on early returns too.
struct Payload {
    record: Asset,
    bytes: Zeroizing<Vec<u8>>,
}

/// Own the bounded asset set until the new database has been persistently
/// quarantined. Early failures drop and zeroize all captured private bytes.
#[derive(Default)]
struct Capture {
    files: BTreeMap<String, Payload>,
    total: usize,
}

impl Capture {
    fn add(&mut self, name: &str, bytes: Zeroizing<Vec<u8>>) -> io::Result<()> {
        let total = self
            .total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("snapshot asset size overflow"))?;
        if self.files.len() >= MAX_ASSETS
            || bytes.len() > MAX_ASSET
            || total > MAX_TOTAL
            || self.files.contains_key(name)
            || !portable_name(name)
        {
            return Err(invalid(
                "snapshot asset inventory exceeds its bounds or repeats a name",
            ));
        }
        let record = Asset {
            name: name.into(),
            bytes: bytes.len(),
            sha256: hex(&bytes),
        };
        self.files.insert(name.into(), Payload { record, bytes });
        self.total = total;
        Ok(())
    }

    fn file(&mut self, name: &str, source: &Path, private: bool) -> io::Result<PathBuf> {
        self.add(name, files::read(source, MAX_ASSET, private)?)?;
        Ok(PathBuf::from(format!("files/{name}")))
    }

    fn bytes(&self, name: &str) -> io::Result<&[u8]> {
        self.files
            .get(name)
            .map(|file| file.bytes.as_slice())
            .ok_or_else(|| invalid("snapshot is missing a captured identity"))
    }

    fn write(self, directory: &Path) -> io::Result<Vec<Asset>> {
        files::create_directory(directory)?;
        let mut records = Vec::with_capacity(self.files.len());
        for (_, file) in self.files {
            files::write(directory, &file.record.name, &file.bytes)?;
            records.push(file.record);
        }
        Ok(records)
    }
}

/// Only non-secret identifiers and scope appear on stdout. The raw manifest
/// and any key/account/order contents stay in the private package.
#[derive(Debug, Serialize)]
pub(super) struct Report {
    node_id: String,
    snapshot_id: String,
    schema_version: u32,
    /// Logical database content only, not complete configuration or freshness.
    /// Legacy identity archives report None and cannot supply this commitment.
    database_content_sha256: Option<String>,
    assets: usize,
    quarantined: bool,
    validation: &'static str,
    acme_cache_semantics: &'static str,
    /// A binding checked locally, never a persistent freshness/activation permit.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sequence: Option<String>,
}

pub(super) fn run(command: Command) -> io::Result<()> {
    let report = match command {
        Command::Configure {
            plan,
            surface,
            output,
        } => {
            return print_report(&configure(&plan, surface, &output)?);
        }
        Command::Create {
            data_dir,
            config,
            output,
        } => create(&super::directory(data_dir)?, &config, &output)?,
        Command::Verify { input } => verify(&input)?,
        Command::Seal { data_dir, input } => seal(&super::directory(data_dir)?, &input)?,
    };
    print_report(&report)
}

fn print_report(report: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), report)
        .map_err(|_| io::Error::other("cannot encode snapshot result"))?;
    writeln!(io::stdout().lock())
}

/// Paths and scope only. The private description contains no copied keys and
/// is not evidence that a running process uses the selected launch plan.
#[derive(Debug, Serialize)]
pub(super) struct ConfigurationReport {
    node_id: String,
    data_dir: PathBuf,
    configuration: PathBuf,
    scope: &'static str,
}

/// Export the existing plan's validated choices without executing its scripts.
/// Health, background observation and egress choices are absent from plans;
/// operators must add later serve overrides before capturing their instance.
pub(super) fn configure(
    plan: &Path,
    surface: config::Surface,
    output: &Path,
) -> io::Result<ConfigurationReport> {
    let output = files::output_path(output)?;
    let (data_dir, configuration) = super::setup::snapshot_configuration(plan, surface)?;
    let bytes = serde_json::to_vec_pretty(&configuration)
        .map_err(|_| io::Error::other("cannot encode private snapshot configuration"))?;
    if bytes.len() > 32 * 1024 {
        return Err(invalid("snapshot configuration exceeds its limit"));
    }
    files::create_directory(&output)?;
    files::write(&output, "configuration.json", &bytes)?;
    Ok(ConfigurationReport {
        node_id: configuration.expected_node_id,
        data_dir,
        configuration: output.join("configuration.json"),
        scope: "selected_launch_plan_only_review_later_serve_overrides",
    })
}

/// Capture once under the original source author/update guards. Read only the
/// explicitly declared assets and the selected ACME namespace; no wildcard
/// source traversal, service stop or permission repair occurs. Source mode
/// contacts only its declared original witness and advances a floor-only seal.
pub(super) fn create(
    directory: &Path,
    configuration_path: &Path,
    output: &Path,
) -> io::Result<Report> {
    let configuration_path = std::path::absolute(configuration_path)?;
    let base = fs::canonicalize(
        configuration_path
            .parent()
            .ok_or_else(|| invalid("snapshot configuration requires a parent directory"))?,
    )?;
    let encoded = files::read(&configuration_path, 32 * 1024, true)?;
    let configuration: Configuration = serde_json::from_slice(&encoded)
        .map_err(|_| invalid("invalid snapshot configuration JSON"))?;
    configuration.validate()?;
    create_from_configuration(directory, &base, configuration, output)
}

fn create_from_configuration(
    directory: &Path,
    base: &Path,
    configuration: Configuration,
    output: &Path,
) -> io::Result<Report> {
    let source = fs::canonicalize(directory)?;
    let output = files::output_path(output)?;
    if source.starts_with(&output) || output.starts_with(&source) {
        return Err(invalid(
            "snapshot output must be outside the source directory and its ancestors",
        ));
    }
    let author = Arc::new(store::lock(&source)?);
    let update = store::update_lock(&source)?;
    let status = store::recovery::status(&source)?;
    if status.node_id != configuration.expected_node_id {
        return Err(invalid(
            "snapshot source node ID does not match configuration",
        ));
    }
    if status
        .recovery
        .as_ref()
        .is_some_and(|record| record.phase != store::recovery::Phase::Ready)
    {
        return Err(invalid(
            "pending recovery cannot be captured as a new identity snapshot",
        ));
    }
    let inputs::Prepared {
        configuration,
        capture,
        acme_cache,
        node,
        #[cfg(feature = "witness-journal")]
            node_listener: _,
        node_key_sha256,
        proxy,
        management,
        health,
    } = inputs::capture(
        &source,
        author.clone(),
        base,
        configuration,
        inputs::Mode::Archive,
    )?;
    if status
        .recovery
        .as_ref()
        .is_some_and(|record| record.node_key_sha256 != node_key_sha256)
    {
        return Err(invalid(
            "captured node identity differs from its recovery pin",
        ));
    }
    #[cfg(feature = "witness-journal")]
    let witness = if let Some(binding) = &configuration.source {
        Some(self::source::Witness::new(
            &source,
            author.clone(),
            binding,
            node,
        )?)
    } else {
        None
    };
    #[cfg(not(feature = "witness-journal"))]
    drop(node);
    // Export does not admit these real prepared objects to a runtime. The fixed
    // configuration path can instead retain them without any input reread.
    drop((proxy, management, health));
    // The marker is persisted before copying SQL. Retained credentials and all
    // private TLS material become a complete package only behind the SQL fence.
    files::create_directory(&output)?;
    let native = || {
        store::create_identity_snapshot(
            &source,
            &output.join("database"),
            &author,
            &update,
            node_key_sha256,
        )
    };
    #[cfg(feature = "witness-journal")]
    let database = match &witness {
        Some(witness) => {
            witness.capture_database(&update, &output.join("database"), node_key_sha256)?
        }
        None => native()?,
    };
    #[cfg(not(feature = "witness-journal"))]
    let database = native()?;
    let record = store::recovery::status(&output.join("database"))?
        .recovery
        .ok_or_else(|| invalid("snapshot SQL fence is missing"))?;
    let assets = capture.write(&output.join("files"))?;
    let manifest = Manifest {
        format_version: if configuration.source.is_some() { 2 } else { 1 },
        platform: std::env::consts::OS.into(),
        snapshot_id: record.id,
        configuration_source: "operator_declared".into(),
        database,
        configuration,
        acme_cache,
        assets,
    };
    check_contents(&output, &manifest, Stage::Preparing)?;
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| io::Error::other("cannot encode private snapshot manifest"))?;
    if bytes.len() > MAX_MANIFEST {
        return Err(invalid("snapshot manifest exceeds its limit"));
    }
    files::write(&output, MANIFEST, &bytes)?;
    #[cfg(feature = "witness-journal")]
    if let Some(witness) = &witness {
        witness.seal(&update, &output, &manifest, &bytes, false)?;
    }
    verify(&output)
}

/// Verify exact private files and archived static configuration. Certificates
/// are checked at the recorded capture time, not accepted for a live handshake;
/// restore/startup must independently check current validity and authorization.
pub(super) fn verify(input: &Path) -> io::Result<Report> {
    files::check_directory(input, true)?;
    let bytes = files::read(&input.join(MANIFEST), MAX_MANIFEST, true)?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid snapshot manifest"))?;
    check_contents(input, &manifest, Stage::Complete)?;
    #[cfg(feature = "witness-journal")]
    let source_sequence = if manifest.configuration.source.is_some() {
        Some(
            self::source::evidence(input, &manifest, &bytes)?
                .transition()
                .sequence
                .clone(),
        )
    } else {
        None
    };
    #[cfg(not(feature = "witness-journal"))]
    let source_sequence = None;
    if files::read(&input.join(MANIFEST), MAX_MANIFEST, true)?.as_slice() != bytes.as_slice() {
        return Err(invalid("snapshot manifest changed while being verified"));
    }
    Ok(Report {
        node_id: manifest.database.node_id,
        snapshot_id: manifest.snapshot_id,
        schema_version: manifest.database.schema_version,
        database_content_sha256: manifest.database.database_content_sha256,
        assets: manifest.assets.len(),
        quarantined: true,
        validation: if manifest.configuration.source.is_some() {
            "integrity_and_sealed_binding_not_current_witness_or_activation"
        } else {
            "integrity_and_archived_static_configuration_not_activation"
        },
        acme_cache_semantics: if manifest.acme_cache.is_some() {
            "preserved_for_separate_recovery_review"
        } else {
            "not_selected"
        },
        source_sequence,
    })
}

/// Continue only an existing prepared Source package. Native descriptions and
/// builds without journaling cannot silently fall back to an unwitnessed seal.
pub(super) fn seal(directory: &Path, input: &Path) -> io::Result<Report> {
    #[cfg(feature = "witness-journal")]
    {
        source::seal(directory, input)
    }
    #[cfg(not(feature = "witness-journal"))]
    {
        let _ = (directory, input);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "witnessed snapshot sealing requires witness-journal",
        ))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Preparing,
    Sealing,
    Complete,
}

fn check_contents(input: &Path, manifest: &Manifest, stage: Stage) -> io::Result<()> {
    if !matches!(
        (
            manifest.format_version,
            manifest.configuration.source.is_some()
        ),
        (1, false) | (2, true)
    ) || manifest.configuration_source != "operator_declared"
        || manifest.assets.len() > MAX_ASSETS
        || !store::valid_id(&manifest.snapshot_id)
    {
        return Err(invalid("invalid snapshot format or identity"));
    }
    if manifest.platform != std::env::consts::OS {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot static validation requires its source platform",
        ));
    }
    manifest.configuration.validate()?;
    let database = store::verify_backup(&input.join("database"))?;
    if database != manifest.database || database.node_id != manifest.configuration.expected_node_id
    {
        return Err(invalid(
            "snapshot database does not match its private manifest",
        ));
    }
    let status = store::recovery::status(&input.join("database"))?;
    let record = status
        .recovery
        .ok_or_else(|| invalid("identity snapshot is missing its SQL fence"))?;
    if record.phase != store::recovery::Phase::PendingTakeover || record.id != manifest.snapshot_id
    {
        return Err(invalid("identity snapshot is not quarantined"));
    }
    let mut expected_root = if stage != Stage::Preparing {
        BTreeSet::from(["database", "files", MANIFEST])
    } else {
        BTreeSet::from(["database", "files"])
    };
    if manifest.configuration.source.is_some()
        && (stage == Stage::Complete
            || (stage == Stage::Sealing && input.join("source").try_exists()?))
    {
        expected_root.insert("source");
    }
    let mut root = BTreeSet::new();
    for (index, entry) in fs::read_dir(input)?.enumerate() {
        if index >= expected_root.len() {
            return Err(invalid("snapshot contains too many root entries"));
        }
        root.insert(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid snapshot filename"))?,
        );
    }
    if root.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected_root {
        return Err(invalid("snapshot contains unexpected root entries"));
    }
    files::check_directory(&input.join("files"), true)?;
    let mut declared = BTreeSet::new();
    let mut total = 0_usize;
    for asset in &manifest.assets {
        if !portable_name(&asset.name)
            || !declared.insert(asset.name.as_str())
            || asset.bytes > MAX_ASSET
        {
            return Err(invalid("invalid snapshot asset inventory"));
        }
        total = total
            .checked_add(asset.bytes)
            .ok_or_else(|| invalid("snapshot asset size overflow"))?;
        if total > MAX_TOTAL {
            return Err(invalid("snapshot assets exceed their total limit"));
        }
        let bytes = files::read(&input.join("files").join(&asset.name), MAX_ASSET, true)?;
        if bytes.len() != asset.bytes || hex(&bytes) != asset.sha256 {
            return Err(invalid("snapshot asset checksum differs"));
        }
    }
    let actual = fs::read_dir(input.join("files"))?
        .enumerate()
        .map(|(index, entry)| {
            if index >= MAX_ASSETS {
                return Err(invalid("snapshot contains too many asset entries"));
            }
            entry.and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("invalid snapshot asset filename"))
            })
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    if actual.iter().map(String::as_str).collect::<BTreeSet<_>>() != declared {
        return Err(invalid("snapshot asset set differs"));
    }
    let config = &manifest.configuration;
    let mut required = BTreeSet::from([
        "node-ca.pem".to_owned(),
        "node.pem".to_owned(),
        "node.key".to_owned(),
    ]);
    check_reference(&config.node.ca, "node-ca.pem")?;
    check_reference(&config.node.certificate, "node.pem")?;
    check_reference(&config.node.private_key, "node.key")?;
    let at = database.created_at_unix_ms / 1000;
    let key = tls::archived_node_identity(
        &input.join(&config.node.ca),
        &input.join(&config.node.certificate),
        &input.join(&config.node.private_key),
        &origin_name(&config.node.origin)?,
        at,
    )?;
    if key != record.node_key_sha256 {
        return Err(invalid(
            "snapshot identity differs from its persistent key pin",
        ));
    }
    match &config.management.tls {
        Tls::Manual {
            certificate,
            private_key,
        } => {
            if manifest.acme_cache.is_some() {
                return Err(invalid("manual TLS snapshot must not contain ACME state"));
            }
            check_reference(certificate, "admin.pem")?;
            check_reference(private_key, "admin.key")?;
            required.extend(["admin.pem".into(), "admin.key".into()]);
            tls::admin_server_config(&input.join(certificate), &input.join(private_key))?;
            let leaf = tls::read_certificate_leaf(&input.join(certificate))?;
            tls::verify_peer_name(&leaf, &origin_name(&config.management.origin)?)?;
            if tls::node_key_sha256(&input.join(private_key))? == key {
                return Err(invalid(
                    "management and node identities must be independent",
                ));
            }
        }
        Tls::Acme { options } => {
            let metadata = manifest
                .acme_cache
                .as_ref()
                .ok_or_else(|| invalid("ACME snapshot cache presence is not recorded"))?;
            for name in acme::backup::verify(
                metadata,
                &config.management.origin,
                options,
                &input.join("files"),
            )? {
                required.insert(format!("acme-{name}"));
            }
        }
    }
    if let Some(path) = &config.proxy_config {
        check_reference(path, "proxy.json")?;
        required.insert("proxy.json".into());
        required.extend(super::proxy::check_snapshot_configuration(
            &input.join(path),
        )?);
    }
    if let Some(path) = &config.health_config {
        check_reference(path, "health.json")?;
        required.insert("health.json".into());
        super::api::check_health_configuration(&input.join(path))?;
    }
    if required.iter().map(String::as_str).collect::<BTreeSet<_>>() != declared {
        return Err(invalid(
            "snapshot configuration does not exactly cover its assets",
        ));
    }
    #[cfg(feature = "witness-journal")]
    if let Some(binding) = &manifest.configuration.source {
        let sha256 = configuration_sha256(manifest)?;
        store::read_backup_verified(&input.join("database"), |connection, database| {
            if *database != manifest.database {
                return Err(invalid(
                    "snapshot database changed during configuration check",
                ));
            }
            store::journal::snapshot::check_configuration(connection, &binding.enrollment, sha256)
        })?;
    }
    Ok(())
}

/// Bind portable typed choices and the exact captured static-file inventory,
/// not source paths or SQL state. ACME's automatically renewed cache is not a
/// runtime choice; its issuance options remain included in Configuration, and
/// the complete cache is still covered separately by the package seal.
#[cfg(feature = "witness-journal")]
fn configuration_sha256(manifest: &Manifest) -> io::Result<[u8; 32]> {
    static_configuration_sha256(
        &manifest.platform,
        &manifest.configuration,
        manifest.assets.iter(),
    )
}

#[cfg(feature = "witness-journal")]
fn static_configuration_sha256<'a>(
    platform: &str,
    configuration: &Configuration,
    assets: impl Iterator<Item = &'a Asset>,
) -> io::Result<[u8; 32]> {
    let mut assets = assets
        .filter(|asset| {
            !matches!(configuration.management.tls, Tls::Acme { .. })
                || !asset.name.starts_with("acme-")
        })
        .collect::<Vec<_>>();
    assets.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    let mut hash = Sha256::new();
    hash.update(b"vproxy.source.runtime-configuration.v1\0");
    for bytes in [
        serde_json::to_vec(platform),
        serde_json::to_vec(configuration),
        serde_json::to_vec(&assets),
    ] {
        let bytes = bytes.map_err(|_| invalid("cannot encode configuration binding"))?;
        hash.update(
            u64::try_from(bytes.len())
                .map_err(|_| invalid("configuration size overflow"))?
                .to_be_bytes(),
        );
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}

/// Internal fixed-input registration, not public Source setup/startup. Current
/// CLI/serve refusal gates remain; callers keep no result until confirmation.
/// Run synchronously on a CLI thread or an owned blocking worker, never directly
/// on an async executor: the offline witness owns its bounded local runtime.
#[cfg(feature = "witness-journal")]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "Source setup is not exposed before full activation gates"
    )
)]
pub(in crate::manage) fn register_configuration(
    directory: &Path,
    configuration: &Path,
    expected_revision: u64,
    resume: bool,
) -> io::Result<Registered> {
    source::register_configuration(directory, configuration, expected_revision, resume)
}

/// Test/owning exporter access uses an already validated private package; no
/// arbitrary JSON or asset hashes are accepted as an observation of a runtime.
#[cfg(all(test, feature = "witness-journal"))]
pub(in crate::manage) fn archived_configuration_sha256(input: &Path) -> io::Result<[u8; 32]> {
    verify(input)?;
    let bytes = files::read(&input.join(MANIFEST), MAX_MANIFEST, true)?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid snapshot manifest"))?;
    configuration_sha256(&manifest)
}

fn check_reference(path: &Path, name: &str) -> io::Result<()> {
    if path.to_str() != Some(format!("files/{name}").as_str()) {
        return Err(invalid(
            "snapshot references must use their fixed portable paths",
        ));
    }
    Ok(())
}

fn resolve_source(base: &Path, path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .to_str()
            .is_none_or(|path| path.chars().any(char::is_control))
    {
        return Err(invalid(
            "snapshot input paths require UTF-8 without controls",
        ));
    }
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    })
}

fn portable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn origin_name(origin: &str) -> io::Result<String> {
    url::Url::parse(origin)
        .ok()
        .and_then(|url| {
            url.host_str().map(|name| {
                name.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned()
            })
        })
        .ok_or_else(|| invalid("invalid snapshot origin"))
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(all(test, feature = "witness-journal"))]
mod binding_tests {
    //! Pure commitment projections only. Actual private files, TLS, SQL and
    //! witness exchanges are covered by the Source export integration tests.
    use super::*;

    fn manifest(automatic: bool) -> io::Result<Manifest> {
        let tls = if automatic {
            serde_json::json!({"mode":"acme","options":{
                "enabled":true,"accept_terms":true,"production":false,
                "contacts":["oncall@example.net"],"challenge":"http-01",
                "http_bind":"127.0.0.1:2080"
            }})
        } else {
            serde_json::json!({"mode":"manual","certificate":"files/admin.pem","private_key":"files/admin.key"})
        };
        serde_json::from_value(serde_json::json!({
        "format_version":2,"platform":"linux","snapshot_id":"AAAAAAAAAAAAAAAAAAAAAA",
        "configuration_source":"operator_declared",
        "database":{"format_version":1,"application_id":0,"schema_version":26,
            "node_id":"AAAAAAAAAAAAAAAAAAAAAA","database_bytes":1,
            "database_sha256":"0".repeat(64),"created_at_unix_ms":0},
        "configuration":{"format_version":2,"expected_node_id":"AAAAAAAAAAAAAAAAAAAAAA",
            "management":{"bind":"127.0.0.1:24443","origin":"https://admin.example:24443",
                "surface":"api_only","tls":tls},
            "node":{"bind":"127.0.0.1:24444","origin":"https://client.example:24444",
                "ca":"files/node-ca.pem","certificate":"files/node.pem","private_key":"files/node.key"},
            "proxy_config":null,"health_config":null,"observe_target_alerts":false,"egress":null,
            "source":{"endpoint":"https://witness.example:24444","enrollment":{
                "witness_node_id":"AQEBAQEBAQEBAQEBAQEBAQ","peer_node_id":"AAAAAAAAAAAAAAAAAAAAAA",
                "binding_id":"AgICAgICAgICAgICAgICAg","writer_id":"AwMDAwMDAwMDAwMDAwMDAw","baseline":"0".repeat(64)
            }}},
        "acme_cache":null,"assets":[
            {"name":"node.pem","bytes":3,"sha256":"1".repeat(64)},
            {"name":"node.key","bytes":4,"sha256":"2".repeat(64)}
        ]
    })).map_err(io::Error::other)
    }

    #[test]
    fn configuration_digest_binds_choices_static_assets_and_platform_not_package_identity()
    -> io::Result<()> {
        let mut m = manifest(false)?;
        m.configuration.validate()?;
        let original = configuration_sha256(&m)?;
        m.assets.reverse();
        m.snapshot_id = "BAQEBAQEBAQEBAQEBAQEBA".into();
        m.database.created_at_unix_ms = 1;
        assert_eq!(configuration_sha256(&m)?, original);
        m.assets[0].sha256 = "3".repeat(64);
        assert_ne!(configuration_sha256(&m)?, original);
        m.assets[0].sha256 = "2".repeat(64);
        m.configuration.observe_target_alerts = true;
        assert_ne!(configuration_sha256(&m)?, original);
        m.configuration.observe_target_alerts = false;
        m.platform = "windows".into();
        assert_ne!(configuration_sha256(&m)?, original);
        m.platform = "linux".into();
        m.configuration
            .source
            .as_mut()
            .ok_or_else(|| invalid("test binding absent"))?
            .endpoint = "https://another.example:24444".into();
        assert_ne!(configuration_sha256(&m)?, original);
        Ok(())
    }

    #[test]
    fn acme_cache_rotation_is_excluded_but_issuance_choices_and_static_files_are_bound()
    -> io::Result<()> {
        let mut m = manifest(true)?;
        m.configuration.validate()?;
        let original = configuration_sha256(&m)?;
        m.assets.push(Asset {
            name: "acme-certificate.pem".into(),
            bytes: 100,
            sha256: "3".repeat(64),
        });
        assert_eq!(configuration_sha256(&m)?, original);
        m.assets
            .last_mut()
            .ok_or_else(|| invalid("test asset absent"))?
            .sha256 = "4".repeat(64);
        assert_eq!(configuration_sha256(&m)?, original);
        m.assets[0].sha256 = "5".repeat(64);
        assert_ne!(configuration_sha256(&m)?, original);
        m.assets[0].sha256 = "1".repeat(64);
        let mut options = serde_json::to_value(&m.configuration).map_err(io::Error::other)?;
        options["management"]["tls"]["options"]["production"] = true.into();
        m.configuration = serde_json::from_value(options).map_err(io::Error::other)?;
        assert_ne!(configuration_sha256(&m)?, original);
        Ok(())
    }
}
