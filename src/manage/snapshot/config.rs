//! Explicit operator-declared startup choices, not an observation of a running
//! process. All optional choices must be present as null or a selected value.
//! Paths are local inputs during capture and fixed relative references on disk.

use std::{collections::HashSet, io, net::SocketAddr, num::NonZeroU32, path::PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::invalid;

/// One versioned description for all startup inputs carried by this snapshot.
/// It grants no authority to run the configuration or replay saved ACME work.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Configuration {
    pub(in crate::manage) format_version: u8,
    pub(in crate::manage) expected_node_id: String,
    pub(in crate::manage) management: Management,
    pub(in crate::manage) node: Node,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(in crate::manage) proxy_config: Option<PathBuf>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(in crate::manage) health_config: Option<PathBuf>,
    pub(in crate::manage) observe_target_alerts: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(in crate::manage) egress: Option<Egress>,
    /// Only format 2 selects witnessed export. Older Native descriptions omit
    /// this field; absence never enables or silently downgrades Source capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::manage) source: Option<Source>,
}

/// Explicit original witness origin and immutable enrollment, not a runtime
/// enable flag, new peer registration or infrastructure-fencing declaration.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Source {
    pub(in crate::manage) endpoint: String,
    pub(in crate::manage) enrollment: crate::manage::witness::Enrollment,
}

/// Browser/API endpoint choices; the selected surface is only declared intent.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Management {
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) origin: String,
    pub(in crate::manage) surface: Surface,
    pub(in crate::manage) tls: Tls,
}

/// The intended installed binary, not a claim about this capture program's
/// feature set or whether any listener has been successfully started.
#[derive(Clone, Copy, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    ApiOnly,
    Web,
}

/// Preserve the selected issuance mode without constructing an issuer. Manual
/// assets are copied; ACME options select one separately preserved cache scope.
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::manage) enum Tls {
    Manual {
        certificate: PathBuf,
        private_key: PathBuf,
    },
    Acme {
        options: crate::manage::acme::PlanOptions,
    },
}

/// Node mTLS is mandatory for retained-identity snapshots. A database-only node
/// can still use the original backup and safe new-identity restore commands.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Node {
    pub(in crate::manage) bind: SocketAddr,
    pub(in crate::manage) origin: String,
    pub(in crate::manage) ca: PathBuf,
    pub(in crate::manage) certificate: PathBuf,
    pub(in crate::manage) private_key: PathBuf,
}

/// Platform-independent data about the intended Linux backend. Inspection does
/// not resolve interfaces, load BPF, replace filters or reserve map capacity.
/// Future activation must revalidate host capabilities and attachment consent.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::manage) struct Egress {
    interfaces: Vec<String>,
    allow_legacy_tc: bool,
    replace_stale_legacy_tc: bool,
    map_capacity: NonZeroU32,
}

impl Configuration {
    /// Pure binary-capability check before any transport/runtime or kernel work.
    /// Static capture is portable and intentionally does not call this check.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) fn check_egress_support(&self) -> io::Result<()> {
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        if self.egress.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "registered egress requires the Linux eBPF backend",
            ));
        }
        Ok(())
    }

    /// Apply exactly the declared backend on the original startup thread,
    /// before Tokio or a Source worker exists. Unsupported platforms/features
    /// reject a selected backend instead of silently using native sockets.
    /// This may attach kernel programs; capture/verify never calls it.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) fn load_egress(&self) -> io::Result<crate::ebpf::Config> {
        self.validate()?;
        self.check_egress_support()?;
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        if let Some(egress) = &self.egress {
            return crate::ebpf::Config::try_new(Some(crate::ebpf::LinuxConfig {
                interfaces: &egress.interfaces,
                allow_legacy_tc: egress.allow_legacy_tc,
                replace_stale_legacy_tc: egress.replace_stale_legacy_tc,
                map_capacity: egress.map_capacity.get(),
            }));
        }
        crate::ebpf::Args::default().load()
    }

    /// Check bounded pure choices before claiming output. Certificate and
    /// referenced-file validation happen on the captured private copy, not on
    /// a different read of the source. No port or kernel availability is implied.
    pub(in crate::manage) fn validate(&self) -> io::Result<()> {
        if !matches!(
            (self.format_version, self.source.is_some()),
            (1, false) | (2, true)
        ) || !crate::manage::store::valid_id(&self.expected_node_id)
        {
            return Err(invalid(
                "invalid snapshot configuration identity or version",
            ));
        }
        if let Some(source) = &self.source {
            source.enrollment.validate()?;
            let origin = crate::manage::api::PublicOrigin::parse(&source.endpoint)?;
            if source.enrollment.peer_node_id != self.expected_node_id
                || origin.value() != source.endpoint
            {
                return Err(invalid(
                    "snapshot source enrollment or canonical witness origin differs",
                ));
            }
            #[cfg(not(feature = "witness-journal"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "witnessed snapshot export requires witness-journal",
            ));
        }
        crate::manage::api::PublicOrigin::parse(&self.management.origin)?;
        crate::manage::api::PublicOrigin::parse(&self.node.origin)?;
        if self.management.origin == self.node.origin
            || self.management.bind.port() == 0
            || self.node.bind.port() == 0
            || self.management.bind == self.node.bind
        {
            return Err(invalid(
                "snapshot requires separate non-zero management and node endpoints",
            ));
        }
        if let Tls::Acme { options } = &self.management.tls {
            options.arguments(&self.management.origin)?;
        }
        if let Some(egress) = &self.egress {
            let mut names = HashSet::new();
            if egress.interfaces.is_empty()
                || egress.interfaces.len() > 64
                || egress.replace_stale_legacy_tc && !egress.allow_legacy_tc
                || egress.interfaces.iter().any(|name| {
                    name.is_empty()
                        || name.len() > 15
                        || name.bytes().any(|byte| {
                            byte == 0 || byte == b'/' || byte == b':' || byte.is_ascii_whitespace()
                        })
                        || !names.insert(name)
                })
            {
                return Err(invalid("invalid snapshot egress settings"));
            }
        }
        Ok(())
    }
}
