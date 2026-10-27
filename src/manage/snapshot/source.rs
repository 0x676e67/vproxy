//! Offline capture/sealing and read-only startup preflight. Original guards
//! span exact floor/configuration checks and evidence publication. Network I/O
//! uses the existing bounded node client; no live server or issuer is created.
use super::*;
use crate::manage::node::control::Fetched;
use crate::manage::witness::Record;
use crate::manage::{
    node::control::{Offline, witness::Operation},
    store::journal::snapshot::{Descriptor, Proof, Source},
};
use std::time::Duration;

/// Non-secret reference plus the exact prepared static inputs. Registration is
/// not activation: runtime owners must still establish every Source gate and
/// keep their process author. Secret input bytes never derive Debug/Serialize.
pub(in crate::manage) struct Registered {
    pub(in crate::manage) reference: store::journal::configuration::Reference,
    pub(in crate::manage) inputs: inputs::Prepared,
    directory: PathBuf,
}

impl Registered {
    /// Confirm the current local reference/floor through actual captured mTLS,
    /// before startup effects. The temporary transport runtime is fully joined
    /// on both success and error, including timed-out blocking authorization.
    /// This can wait for real I/O completion; ten-second network timeout alone
    /// is not proof that its blocking workers stopped. The returned update guard
    /// spans kernel preparation, not a lease or same-ID activation/fencing grant.
    pub(in crate::manage) fn preflight(
        &self,
        directory: &Path,
        author: Arc<store::Guard>,
    ) -> io::Result<store::UpdateGuard> {
        author.ensure(directory)?;
        self.validate(directory)?;
        let gate = store::update_lock(directory)?;
        let binding = self
            .inputs
            .configuration
            .source
            .as_ref()
            .ok_or_else(|| invalid("registered source binding required"))?;
        let witness = Witness::new(directory, author.clone(), binding, self.inputs.node.clone())?;
        let result = store::journal::configuration::inspect(
            directory,
            &author,
            &gate,
            &binding.enrollment,
            self.reference,
            &mut |operation| witness.request(operation),
        );
        // No startup continuation may follow a timeout-based runtime teardown:
        // a retained authorization read could still own threads and file guards.
        witness.join();
        result?;
        Ok(gate)
    }

    /// Validate the original directory and complete owned static projection
    /// before kernel preparation. SQL/witness freshness is still checked by the
    /// original worker before serving; a digest alone grants no activation.
    pub(in crate::manage) fn validate(&self, directory: &Path) -> io::Result<()> {
        if fs::canonicalize(directory)? != self.directory
            || self.inputs.sha256()? != self.reference.sha256
            || self.inputs.node.key_sha256()? != self.inputs.node_key_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registered configuration inputs differ",
            ));
        }
        self.inputs.configuration.validate()
    }

    /// Transfer captured inputs only to their original canonical directory.
    /// Recheck the owned projection, not source paths that may have changed.
    /// This does not hold an author or promise that SQL is still at this
    /// reference: the worker must compare it under its original update gate.
    pub(in crate::manage) fn into_inputs(
        mut self,
        directory: &Path,
    ) -> io::Result<(store::journal::configuration::Reference, inputs::Prepared)> {
        self.validate(directory)?;
        self.inputs.node_listener = Some(crate::manage::node::configure_registered(
            &self.inputs,
            self.reference,
        )?);
        Ok((self.reference, self.inputs))
    }
}

/// Capture the complete declared configuration once, without SQL copying or
/// ACME cache access, then use the original file-author configuration kernel.
/// All static validation precedes a witness mutation. Explicit resume accepts
/// only the original exact digest/CAS; this never creates a source enrollment.
/// Join transport workers before returning captured inputs that may proceed
/// directly into startup privilege changes; unknown results remain errors.
pub(super) fn register_configuration(
    directory: &Path,
    configuration_path: &Path,
    expected_revision: u64,
    resume: bool,
) -> io::Result<Registered> {
    let directory = fs::canonicalize(directory)?;
    let author = Arc::new(store::lock(&directory)?);
    let gate = store::update_lock(&directory)?;
    let configuration_path = std::path::absolute(configuration_path)?;
    let base = fs::canonicalize(
        configuration_path
            .parent()
            .ok_or_else(|| invalid("fixed configuration requires a parent directory"))?,
    )?;
    let bytes = files::read(&configuration_path, 32 * 1024, true)?;
    let configuration: Configuration =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid fixed configuration JSON"))?;
    configuration.validate()?;
    if configuration.source.is_none() {
        return Err(invalid(
            "fixed registration requires an existing Source binding",
        ));
    }
    let status = store::recovery::status(&directory)?;
    if status.node_id != configuration.expected_node_id
        || status
            .recovery
            .as_ref()
            .is_some_and(|r| r.phase != store::recovery::Phase::Ready)
    {
        return Err(invalid(
            "fixed configuration node or recovery state differs",
        ));
    }
    let inputs = inputs::capture(
        &directory,
        author.clone(),
        &base,
        configuration,
        inputs::Mode::Fixed,
    )?;
    if status
        .recovery
        .as_ref()
        .is_some_and(|r| r.node_key_sha256 != inputs.node_key_sha256)
    {
        return Err(invalid("fixed node identity differs from its recovery pin"));
    }
    let sha256 = inputs.sha256()?;
    let binding = inputs
        .configuration
        .source
        .as_ref()
        .ok_or_else(|| invalid("fixed source selection disappeared"))?;
    // Clone only the two immutable Arc owners and public metadata: witness I/O
    // and later runtime preparation share this exact chain/signer/roots.
    let witness = Witness::new(&directory, author.clone(), binding, inputs.node.clone())?;
    let desired = store::journal::configuration::Desired {
        expected_revision,
        sha256,
    };
    let mut request = |operation| witness.request(operation);
    let reference = if resume {
        store::journal::configuration::reconcile(
            &directory,
            &author,
            &gate,
            &binding.enrollment,
            &desired,
            &mut request,
        )
    } else {
        store::journal::configuration::accept(
            &directory,
            &author,
            &gate,
            &binding.enrollment,
            &desired,
            &mut request,
        )
    };
    witness.join();
    let reference = reference?;
    Ok(Registered {
        reference,
        inputs,
        directory,
    })
}

pub(super) struct Witness {
    directory: PathBuf,
    author: Arc<store::Guard>,
    binding: config::Source,
    offline: Arc<Offline>,
    runtime: Option<tokio::runtime::Runtime>,
}
impl Witness {
    /// Only startup continuation needs this stronger completion boundary.
    /// Ordinary offline artifact Drop retains its existing bounded shutdown;
    /// preflight must join actual blocking work before changing privileges.
    fn join(mut self) {
        if let Some(runtime) = self.runtime.take() {
            drop(runtime);
        }
    }

    pub(super) fn new(
        directory: &Path,
        author: Arc<store::Guard>,
        binding: &config::Source,
        identity: tls::NodeIdentity,
    ) -> io::Result<Self> {
        let offline = Offline::new(
            directory,
            author.clone(),
            &binding.enrollment.peer_node_id,
            identity,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(4)
            .build()?;
        Ok(Self {
            directory: directory.to_owned(),
            author,
            binding: binding.clone(),
            offline,
            runtime: Some(runtime),
        })
    }
    fn request(&self, operation: Operation) -> io::Result<Fetched<Record>> {
        self.runtime
            .as_ref()
            .ok_or_else(|| invalid("snapshot witness runtime is closed"))?
            .block_on(self.offline.request(
                &self.binding.endpoint,
                &self.binding.enrollment.witness_node_id,
                operation,
            ))
    }
    pub(super) fn capture_database(
        &self,
        gate: &store::UpdateGuard,
        output: &Path,
        key: [u8; 32],
    ) -> io::Result<store::BackupManifest> {
        Source::new(
            &self.directory,
            &self.author,
            gate,
            &self.binding.enrollment,
        )
        .capture_database(output, key, &mut |operation| self.request(operation))
    }
    pub(super) fn seal(
        &self,
        gate: &store::UpdateGuard,
        input: &Path,
        manifest: &Manifest,
        bytes: &[u8],
        resume: bool,
    ) -> io::Result<()> {
        // Verify all base bytes immediately before network mutation. Existing
        // source evidence is never part of its own descriptor digest.
        check_contents(input, manifest, Stage::Sealing)?;
        if files::read(&input.join(MANIFEST), MAX_MANIFEST, true)?.as_slice() != bytes {
            return Err(invalid("snapshot manifest changed before sealing"));
        }
        let descriptor = descriptor(manifest, bytes)?;
        Source::new(
            &self.directory,
            &self.author,
            gate,
            &self.binding.enrollment,
        )
        .seal(
            &descriptor,
            resume,
            &input.join("source"),
            &mut |operation| self.request(operation),
        )?;
        Ok(())
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

fn descriptor(manifest: &Manifest, bytes: &[u8]) -> io::Result<Descriptor> {
    Ok(Descriptor {
        snapshot_id: manifest.snapshot_id.clone(),
        package_sha256: hex(bytes),
        database_content_sha256: manifest
            .database
            .database_content_sha256
            .clone()
            .ok_or_else(|| invalid("snapshot has no logical database commitment"))?,
    })
}

/// Read-only local binding verification. No archived JSON is promoted to an
/// authenticated Fetched record or accepted as a current-witness/activation grant.
pub(super) fn evidence(input: &Path, manifest: &Manifest, bytes: &[u8]) -> io::Result<Proof> {
    let descriptor = descriptor(manifest, bytes)?;
    let binding = manifest
        .configuration
        .source
        .as_ref()
        .ok_or_else(|| invalid("snapshot is not a Source package"))?;
    let marker = files::read(&input.join("database/snapshot.json"), 1024, true)?;
    let marker: store::recovery::Snapshot =
        serde_json::from_slice(&marker).map_err(|_| invalid("snapshot marker is malformed"))?;
    store::read_backup_verified(&input.join("database"), |connection, database| {
        if *database != manifest.database {
            return Err(invalid(
                "snapshot database manifest changed before evidence verification",
            ));
        }
        let proof = store::journal::snapshot::evidence(
            &input.join("source"),
            connection,
            &descriptor,
            marker.previous_key(),
            &binding.enrollment,
        )?;
        Ok(proof)
    })
}

/// Explicit continuation uses only this prepared package and its original
/// descriptor. It never captures another database, generates a new snapshot ID
/// or reconciles an unrelated retained operation. Existing output is not reset.
pub(super) fn seal(directory: &Path, input: &Path) -> io::Result<Report> {
    files::check_directory(input, true)?;
    let directory = fs::canonicalize(directory)?;
    let input = fs::canonicalize(input)?;
    if directory.starts_with(&input) || input.starts_with(&directory) {
        return Err(invalid(
            "snapshot package must remain outside the source directory and its ancestors",
        ));
    }
    let bytes = files::read(&input.join(MANIFEST), MAX_MANIFEST, true)?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid snapshot manifest"))?;
    check_contents(&input, &manifest, Stage::Sealing)?;
    let binding = manifest
        .configuration
        .source
        .as_ref()
        .ok_or_else(|| invalid("only witnessed snapshots require sealing"))?;
    let author = Arc::new(store::lock(&directory)?);
    let update = store::update_lock(&directory)?;
    let node = &manifest.configuration.node;
    // Live construction checks current certificate validity, unlike local
    // integrity verification at the archive's recorded capture time.
    let identity = tls::node_identity(
        &input.join(&node.ca),
        &input.join(&node.certificate),
        &input.join(&node.private_key),
    )?;
    let witness = Witness::new(&directory, author, binding, identity)?;
    witness.seal(&update, &input, &manifest, &bytes, true)?;
    verify(&input)
}

#[cfg(test)]
mod preflight_tests {
    //! Real captured mTLS preflight and its stronger runtime completion boundary.
    //! New private fixtures only; no kernel attachment or existing node state.
    use super::*;
    use crate::manage::store::journal::{SourceExportFixture, SourceFixture};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::{sync::oneshot, time::timeout};

    async fn fixture() -> io::Result<SourceExportFixture> {
        let live = SourceFixture::new_with(Default::default(), |_| Ok(())).await?;
        SourceExportFixture::from_live(live).await
    }

    #[tokio::test]
    async fn registered_preflight_uses_captured_mtls_and_returns_the_original_held_update_guard()
    -> io::Result<()> {
        let export = fixture().await?;
        let result = async {
        let registered = export.register(0, false).await?;
        let before = export.floor()?;
        let parent = export.configuration.parent().ok_or_else(||invalid("fixture parent"))?;
        for path in [export.configuration.clone(),parent.join("admin.pem"),parent.join("admin.key"),
            parent.join("node.key"), export.fixture.ca.clone(),export.fixture.client_cert.clone()] {
            fs::remove_file(path)?;
        }
        let directory = export.fixture.client_state.clone();
        let author = Arc::new(store::lock(&directory)?);
        let (registered, author, gate) = tokio::task::spawn_blocking(move || {
            let gate = registered.preflight(&directory, author.clone())?;
            Ok::<_,io::Error>((registered, author, gate))
        }).await.map_err(io::Error::other)??;
        assert!(matches!(store::update_lock(&export.fixture.client_state),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
        assert_eq!(registered.inputs.sha256()?, registered.reference.sha256);
        assert_eq!(export.floor()?, before);
        drop(gate);
        store::update_lock(&export.fixture.client_state)?;
        drop(author);
        store::lock(&export.fixture.client_state)?;
        Ok(())
    }.await;
        result.and(export.close().await)
    }

    #[tokio::test]
    async fn preflight_runtime_join_keeps_author_until_actual_blocking_work_finishes()
    -> io::Result<()> {
        let export = fixture().await?;
        let result = async {
        let registered = export.register(0, false).await?;
        let directory = export.fixture.client_state.clone();
        let (release, waiting) = std::sync::mpsc::channel();
        let (joining, begun) = oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = finished.clone();
        let mut driver = tokio::task::spawn_blocking(move || {
            let author = Arc::new(store::lock(&directory)?);
            let gate = store::update_lock(&directory)?;
            let binding = registered.inputs.configuration.source.as_ref().ok_or_else(||invalid("fixture binding"))?;
            let witness = Witness::new(&directory,author,binding,registered.inputs.node.clone())?;
            let runtime = witness.runtime.as_ref().ok_or_else(||invalid("fixture runtime"))?;
            let (entered, entered_wait) = oneshot::channel();
            // Model an authorization read that outlives its transport deadline.
            // Wait for actual worker entry, not merely acceptance into the pool.
            let worker = runtime.spawn_blocking(move || {
                let _=entered.send(());
                let _=waiting.recv();
                finished.store(true,Ordering::Release);
            });
            runtime.block_on(entered_wait).map_err(io::Error::other)?;
            let _=joining.send(());
            witness.join();
            drop(gate);
            Ok::<_,io::Error>((observed.load(Ordering::Acquire),worker))
        });
        timeout(Duration::from_secs(10),begun).await.map_err(io::Error::other)?.map_err(io::Error::other)?;
        // The former offline Drop bound is five seconds. Waiting beyond it
        // proves that startup does not continue while that worker still runs.
        let early = timeout(Duration::from_secs(6), &mut driver).await;
        let retained = matches!(store::lock(&export.fixture.client_state),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
            && matches!(store::update_lock(&export.fixture.client_state),Err(e) if e.kind()==io::ErrorKind::WouldBlock);
        let _=release.send(());
        let (completed_before_return,worker,was_early) = match early {
            Ok(joined) => {let (done,worker)=joined.map_err(io::Error::other)??;(done,worker,true)}
            Err(_) => {let (done,worker)=timeout(Duration::from_secs(10),driver).await.map_err(io::Error::other)?.map_err(io::Error::other)??;(done,worker,false)}
        };
        worker.await.map_err(io::Error::other)?;
        if was_early || !retained || !completed_before_return {
            return Err(io::Error::other("startup continued before its blocking work stopped"));
        }
        store::lock(&export.fixture.client_state)?;
        store::update_lock(&export.fixture.client_state)?;
        Ok(())
    }.await;
        result.and(export.close().await)
    }
}
