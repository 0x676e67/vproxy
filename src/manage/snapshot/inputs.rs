//! One bounded read of declared static inputs, shared by inert exports and
//! fixed configuration registration. Prepared owners use those exact buffers;
//! they do not grant permission to start a protected runtime.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::manage) enum Mode {
    Archive,
    #[cfg(feature = "witness-journal")]
    Fixed,
}

/// Exact portable bytes plus the objects prepared from them. ACME keeps its
/// issuance choices in Configuration; fixed capture never opens or copies its
/// dynamic cache and does not construct an issuer. An archive preserves it.
/// The declared binary surface, ACME issuer, egress attachment and all Source
/// runtime admission gates still need application before these objects run.
/// This binds static choices, not an attestation of host-derived defaults or
/// capabilities at a later startup.
pub(in crate::manage) struct Prepared {
    pub(in crate::manage) configuration: Configuration,
    pub(super) capture: Capture,
    pub(in crate::manage) acme_cache: Option<acme::backup::Metadata>,
    pub(in crate::manage) node: tls::NodeIdentity,
    /// Filled only when the registered capture is handed to its Source worker.
    /// It holds the same signer/roots, not archived paths or an activation grant.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) node_listener: Option<super::super::node::Config>,
    pub(in crate::manage) node_key_sha256: [u8; 32],
    pub(in crate::manage) proxy: Option<super::super::proxy::Prepared>,
    pub(in crate::manage) management:
        Option<(Arc<rustls::ServerConfig>, super::super::certificates::State)>,
    pub(in crate::manage) health: super::super::health::Config,
}

impl Prepared {
    /// The canonical projection used by archived packages too; dynamic ACME
    /// cache bytes are excluded, not node/management/proxy static identities.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) fn sha256(&self) -> io::Result<[u8; 32]> {
        static_configuration_sha256(
            std::env::consts::OS,
            &self.configuration,
            self.capture.files.values().map(|p| &p.record),
        )
    }
}

/// The caller retains its original author/update guards and checks the node ID
/// and recovery pin in that same scope. Capture validates pure configuration,
/// actual node roots/EKUs/name, manual management name/key and normal proxy/
/// health rules, without binding sockets, attaching BPF or contacting a CA.
pub(in crate::manage) fn capture(
    source: &Path,
    author: Arc<store::Guard>,
    base: &Path,
    mut configuration: Configuration,
    mode: Mode,
) -> io::Result<Prepared> {
    author.ensure(source)?;
    configuration.validate()?;
    let mut capture = Capture::default();
    configuration.node.ca = capture.file(
        "node-ca.pem",
        &resolve_source(base, &configuration.node.ca)?,
        false,
    )?;
    configuration.node.certificate = capture.file(
        "node.pem",
        &resolve_source(base, &configuration.node.certificate)?,
        false,
    )?;
    configuration.node.private_key = capture.file(
        "node.key",
        &resolve_source(base, &configuration.node.private_key)?,
        true,
    )?;
    let node = tls::captured_node_identity(
        capture.bytes("node-ca.pem")?,
        capture.bytes("node.pem")?,
        capture.bytes("node.key")?,
    )?;
    node.verify_name(&origin_name(&configuration.node.origin)?)?;
    let node_key_sha256 = node.key_sha256()?;
    let (management, acme_cache) = match &mut configuration.management.tls {
        Tls::Manual {
            certificate,
            private_key,
        } => {
            *certificate = capture.file("admin.pem", &resolve_source(base, certificate)?, false)?;
            *private_key = capture.file("admin.key", &resolve_source(base, private_key)?, true)?;
            let identity = tls::captured_admin_identity(
                capture.bytes("admin.pem")?,
                capture.bytes("admin.key")?,
                &origin_name(&configuration.management.origin)?,
            )?;
            if tls::key_pem_sha256(capture.bytes("admin.key")?)? == node_key_sha256 {
                return Err(invalid(
                    "management and node identities require independent keys",
                ));
            }
            (Some(identity), None)
        }
        Tls::Acme { options } => {
            let cache = if mode == Mode::Archive {
                let cache = acme::backup::capture(
                    source,
                    author.clone(),
                    &configuration.management.origin,
                    options,
                )?;
                for (name, bytes) in cache.entries {
                    capture.add(&format!("acme-{name}"), bytes)?;
                }
                Some(cache.metadata)
            } else {
                None
            };
            (None, cache)
        }
    };
    let proxy = if let Some(path) = &mut configuration.proxy_config {
        let proxy = super::super::proxy::snapshot_configuration(&resolve_source(base, path)?)?;
        for input in proxy.inputs {
            capture.add(&input.name, input.bytes)?;
        }
        capture.add("proxy.json", Zeroizing::new(proxy.bytes))?;
        *path = PathBuf::from("files/proxy.json");
        Some(proxy.prepared)
    } else {
        None
    };
    let health = if let Some(path) = &mut configuration.health_config {
        *path = capture.file("health.json", &resolve_source(base, path)?, false)?;
        super::super::api::captured_health_configuration(capture.bytes("health.json")?)?
    } else {
        super::super::health::Config::default()
    };
    Ok(Prepared {
        configuration,
        capture,
        acme_cache,
        node,
        #[cfg(feature = "witness-journal")]
        node_listener: None,
        node_key_sha256,
        proxy,
        management,
        health,
    })
}
