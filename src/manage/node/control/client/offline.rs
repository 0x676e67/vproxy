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

#[cfg(test)]
mod tests {
    //! Actual local TLS and changed SQL authority, not JSON-supplied identity proof.
    use super::*;
    use crate::manage::{
        node::tests::Fixture,
        witness::{Enrollment, Phase, Record},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use bytes::Bytes;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn loaded(f: &Fixture) -> io::Result<tls::NodeIdentity> {
        tls::node_identity(&f.ca, &f.client_cert, &f.client_key)
    }

    fn recovery(f: &Fixture, phase: &str, key: [u8; 32]) -> io::Result<()> {
        let connection = rusqlite::Connection::open(f.client_state.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        connection.execute(
            "UPDATE recovery_state SET kind='restored',phase=?1,recovery_id=?2,source_node_id=?3,
             source_schema_version=13,source_database_sha256=?4,node_key_sha256=?5,
             imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",
            rusqlite::params![phase, URL_SAFE_NO_PAD.encode([22_u8;16]), f.server_id, "3".repeat(64), &key[..]],
        ).map_err(io::Error::other)?;
        Ok(())
    }

    #[test]
    fn offline_capability_requires_exact_author_source_and_recovered_resolver() -> io::Result<()> {
        let f = Fixture::new(true, true)?;
        let author = Arc::new(store::lock(&f.client_state)?);
        let wrong_author = Arc::new(store::lock(&f.server_state)?);
        assert_eq!(
            Offline::new(&f.client_state, wrong_author, &f.client_id, loaded(&f)?)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            Offline::new(&f.client_state, author.clone(), &f.server_id, loaded(&f)?)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let key = tls::node_key_sha256(&f.client_key)?;
        recovery(&f, "pending_review", key)?;
        assert_eq!(
            Offline::new(&f.client_state, author.clone(), &f.client_id, loaded(&f)?)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let mut wrong = key;
        wrong[0] ^= 1;
        recovery(&f, "ready", wrong)?;
        assert_eq!(
            Offline::new(&f.client_state, author.clone(), &f.client_id, loaded(&f)?)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        recovery(&f, "ready", key)?;
        let source = Offline::new(&f.client_state, author, &f.client_id, loaded(&f)?)?;
        drop(source);
        // An allowed recovered source still retains its permanent key pin; no
        // fixture mutation made it Native or removed the quarantine machinery.
        assert_eq!(store::recovery::startup(&f.client_state)?, Some(key));
        Ok(())
    }

    #[tokio::test]
    async fn offline_witness_proof_is_tls_derived_and_changes_during_http_are_fenced()
    -> io::Result<()> {
        // Zero is a valid baseline response. The other modes advance the local peer
        // revision or enter PendingReview after HTTP starts but before the response.
        for mode in 0..3 {
            let f = Fixture::new(true, true)?;
            let source = Offline::new(
                &f.client_state,
                Arc::new(store::lock(&f.client_state)?),
                &f.client_id,
                loaded(&f)?,
            )?;
            let enrollment = Enrollment {
                witness_node_id: f.server_id.clone(),
                peer_node_id: f.client_id.clone(),
                binding_id: URL_SAFE_NO_PAD.encode([23_u8; 16]),
                writer_id: URL_SAFE_NO_PAD.encode([24_u8; 16]),
                baseline: "0".repeat(64),
            };
            let record = Record {
                enrollment: enrollment.clone(),
                sequence: "0".into(),
                previous: None,
                commitment: enrollment.baseline.clone(),
                phase: Phase::Confirmed,
                retired: false,
            };
            let body = serde_json::to_vec(&record).map_err(io::Error::other)?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let tls = f.server_tls.clone();
            let directory = f.client_state.clone();
            let peer = f.server_id.clone();
            let key = tls::node_key_sha256(&f.client_key)?;
            let stop = tokio_util::sync::CancellationToken::new();
            let stopped = stop.clone();
            let task = tokio::spawn(async move {
                let (stream, _) = tokio::select! {
                    result=listener.accept()=>result?,
                    _=stopped.cancelled()=>return Ok::<_,io::Error>(()),
                };
                let stream = TlsAcceptor::from(tls).accept(stream).await?;
                let service = service_fn(move |_: hyper::Request<hyper::body::Incoming>| {
                    let directory = directory.clone();
                    let peer = peer.clone();
                    let body = body.clone();
                    async move {
                        tokio::task::spawn_blocking(move || -> io::Result<()> {
                            match mode {
                                1 => { store::set_peer_active(&directory, &peer, 1, true)?; }
                                2 => {
                                    let c=rusqlite::Connection::open(directory.join("management.sqlite3")).map_err(io::Error::other)?;
                                    c.execute("UPDATE recovery_state SET kind='restored',phase='pending_review',recovery_id=?1,source_node_id=?2,source_schema_version=13,source_database_sha256=?3,node_key_sha256=?4,imported_users=0,imported_prefixes=0,imported_addresses=0,imported_pools=0 WHERE singleton=1",rusqlite::params![URL_SAFE_NO_PAD.encode([25_u8;16]),peer,"4".repeat(64),&key[..]]).map_err(io::Error::other)?;
                                }
                                _ => {}
                            } Ok(())
                        }).await.unwrap().unwrap();
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                    .map_err(io::Error::other)
            });
            let result = source
                .request(
                    &format!("https://localhost:{}", address.port()),
                    &f.server_id,
                    witness::Operation {
                        enrollment,
                        action: witness::Action::Inspect,
                    },
                )
                .await;
            stop.cancel();
            task.await.map_err(io::Error::other)??;
            match mode {
                0 => {
                    let value = result?;
                    assert_eq!(value.value, record);
                    assert_eq!(value.authorization.node_id, f.server_id);
                    assert_eq!(value.authorization.authorization_revision, 1);
                    let current =
                        store::authorize_peer(&f.client_state, &value.authorization.leaf)?
                            .ok_or_else(|| {
                                io::Error::other("TLS proof was not the registered leaf")
                            })?;
                    assert_eq!(current.node_id, value.authorization.node_id);
                }
                _ => assert_eq!(
                    result.err().map(|e| e.kind()),
                    Some(io::ErrorKind::PermissionDenied)
                ),
            }
        }
        Ok(())
    }
}
