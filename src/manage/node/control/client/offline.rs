//! Offline witness admission before policy/traffic restoration. The source
//! author outlives every blocking read, even if a network deadline expires.

use super::*;
use crate::manage::tls;
use std::path::{Path, PathBuf};
use tokio::sync::Semaphore;

/// A once-loaded TLS identity and the exact local directory author. No policy
/// verifiers or restored meter state are needed to authorize a witness read.
/// This capability accepts only witness operations for its original node ID;
/// it grants no arbitrary proxy-control or same-ID activation operation.
pub(in crate::manage) struct Offline {
    directory: PathBuf,
    author: Arc<store::Guard>,
    pub(super) node_id: String,
    recovery_key: Option<[u8; 32]>,
    loaded_key: [u8; 32],
    tls: Arc<ClientConfig>,
    work: Arc<Semaphore>,
}

impl Offline {
    /// Synchronous startup under an existing author; no network or migration.
    /// Require the actual TLS resolver to match any permanent recovery key pin.
    /// Pending recovery, wrong author/node, old schema or malformed state fail
    /// before a request can be issued. The parent directory remains trusted.
    pub(in crate::manage) fn new(
        directory: &Path,
        author: Arc<store::Guard>,
        node_id: &str,
        identity: tls::NodeIdentity,
    ) -> io::Result<Arc<Self>> {
        author.ensure(directory)?;
        let overview = store::inspect(directory)?;
        if overview.schema_version < 25 {
            return Err(crate::manage::witness::Error::UpgradeRequired.error());
        }
        if overview.node_id != node_id {
            return Err(denied());
        }
        let recovery_key = store::recovery::diagnostic_startup(directory)?;
        let loaded_key = identity.key_sha256()?;
        if recovery_key.is_some_and(|pin| pin != loaded_key) {
            return Err(denied());
        }
        Ok(Arc::new(Self {
            directory: std::fs::canonicalize(directory)?,
            author,
            node_id: node_id.to_owned(),
            recovery_key,
            loaded_key,
            tls: identity.client_config()?,
            work: Arc::new(Semaphore::new(1)),
        }))
    }

    /// Use the ordinary ten-second transport and return its actual TLS proof.
    /// Cancellation cannot cancel a reservation already accepted remotely;
    /// callers retain the original transition and reconcile uncertain replies.
    /// Importers must recheck proof and source state in their own transaction.
    pub(in crate::manage) async fn request(
        self: &Arc<Self>,
        endpoint: &str,
        expected_peer: &str,
        operation: witness::Operation,
    ) -> io::Result<Fetched<crate::manage::witness::Record>> {
        match request_as(
            Authorization::Offline(self),
            self.tls.clone(),
            endpoint,
            expected_peer,
            Request::Witness(operation),
        )
        .await?
        {
            Reply::Witness(value) => Ok(*value),
            _ => Err(invalid("unexpected witness reply")),
        }
    }

    /// At most one blocking authorization read runs per capability. No permit
    /// spans a network wait and cancellation leaves it with the blocking owner.
    pub(super) async fn authorize(
        self: &Arc<Self>,
        leaf: Arc<[u8]>,
        expected: String,
    ) -> io::Result<u64> {
        let permit = self.work.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "offline witness authorization is busy",
            )
        })?;
        let source = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            source.author.ensure(&source.directory)?;
            let overview = store::inspect(&source.directory)?;
            let recovery_key = store::recovery::diagnostic_startup(&source.directory)?;
            if overview.schema_version < 25
                || overview.node_id != source.node_id
                || recovery_key != source.recovery_key
                || recovery_key.is_some_and(|pin| pin != source.loaded_key)
            {
                return Err(denied());
            }
            authorize_in(&source.directory, &leaf, &expected)
        })
        .await
        .map_err(|_| io::Error::other("offline witness authorization worker failed"))?
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "offline source identity or recovery state differs",
    )
}
