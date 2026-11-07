//! Capture and validate the exact static inputs archived by an inert snapshot.
use super::*;

/// Exact portable bytes and their checked configuration, without runtime owners.
pub(in crate::manage) struct Prepared {
    pub(in crate::manage) configuration: Configuration,
    pub(super) capture: Capture,
    pub(in crate::manage) acme_cache: Option<acme::backup::Metadata>,
    pub(in crate::manage) node_key_sha256: [u8; 32],
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
    let acme_cache = match &mut configuration.management.tls {
        Tls::Manual {
            certificate,
            private_key,
        } => {
            *certificate = capture.file("admin.pem", &resolve_source(base, certificate)?, false)?;
            *private_key = capture.file("admin.key", &resolve_source(base, private_key)?, true)?;
            tls::captured_admin_identity(
                capture.bytes("admin.pem")?,
                capture.bytes("admin.key")?,
                &origin_name(&configuration.management.origin)?,
            )?;
            if tls::key_pem_sha256(capture.bytes("admin.key")?)? == node_key_sha256 {
                return Err(invalid(
                    "management and node identities require independent keys",
                ));
            }
            None
        }
        Tls::Acme { options } => {
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
        }
    };
    if let Some(path) = &mut configuration.proxy_config {
        let proxy = super::super::proxy::snapshot_configuration(&resolve_source(base, path)?)?;
        for input in proxy.inputs {
            capture.add(&input.name, input.bytes)?;
        }
        capture.add("proxy.json", Zeroizing::new(proxy.bytes))?;
        *path = PathBuf::from("files/proxy.json");
    }
    if let Some(path) = &mut configuration.health_config {
        *path = capture.file("health.json", &resolve_source(base, path)?, false)?;
        super::super::api::captured_health_configuration(capture.bytes("health.json")?)?;
    }
    Ok(Prepared {
        configuration,
        capture,
        acme_cache,
        node_key_sha256,
    })
}
