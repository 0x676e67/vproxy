//! One policy application service shared by browser and node transports.
//!
//! Admission state is published once. Blocking workers own the local writer
//! permit, cross-process update gate and process author through commit,
//! publication and receipt, even when their requesting transport disappears.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::{
    drain, maintenance, proxy,
    store::{
        self, CredentialView, PolicyChange, UserView, admission,
        operations::{self, Caller, Input, Operation, Outcome},
    },
    witness::{Record, Transition},
};
use crate::access::{PolicyData, Reader};

const MAX_PENDING_WRITERS: usize = 8;
const WRITER_WAIT: Duration = Duration::from_millis(250);
const MAX_PENDING_READERS: usize = 4;
const INTERNAL_READ_WAIT: Duration = Duration::from_millis(250);

/// Internal checkpoint diagnostics, not transport error codes. In particular,
/// `Store` can mean SQLite contention or a fenced collector, not just a busy DB.
#[derive(Clone, Copy, Debug)]
pub(super) enum TrafficWriteStage {
    Admission,
    UpdateGate,
    Store,
    Worker,
}

/// Keeps the original error intact for callers that classify its concrete
/// source. Only the local collector adds the stage to its private diagnostics.
pub(super) struct TrafficWriteFailure {
    pub(super) stage: TrafficWriteStage,
    pub(super) error: io::Error,
}

/// Internal read diagnostics. SQLite contention is an operation failure even
/// when it has the same `WouldBlock` kind as an exhausted admission budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadStage {
    Admission,
    Operation,
    Worker,
}

/// Preserve the original error for transport classification and typed sources.
/// Diagnostics may project its kind, but must not log its private message.
#[derive(Debug)]
pub(super) struct ReadFailure {
    pub(super) stage: ReadStage,
    pub(super) error: io::Error,
}

/// Admission policy for one blocking read, not a lease across network work.
/// Ordinary requests fail fast. Already-admitted deliveries and single-flight
/// collectors may briefly reserve a place in the same two-worker FIFO queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadAdmission {
    Immediate,
    Internal,
}

/// Typed non-HTTP failures preserve stable wire codes without leaking storage
/// diagnostics or forcing this service to depend on a transport's status codes.
#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("policy publication failed")]
    PublicationFailed,
    #[error("policy worker unavailable")]
    WorkerUnavailable,
}

impl Error {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::PublicationFailed => "policy_publication_failed",
            Self::WorkerUnavailable => "policy_unavailable",
        }
    }
}

/// Public response material only; the full verifier policy moves into `Reader`.
pub(super) struct Change {
    pub(super) revision: u64,
    /// Actual runner flag when this candidate finished publication, not proof
    /// that the process remains running by the time a response is received.
    pub(super) running: bool,
    pub(super) user: Option<UserView>,
    pub(super) credential: Option<CredentialView>,
    pub(super) secret: Option<Zeroizing<String>>,
    pub(super) routing: Option<crate::access::routing::RoutingEntity>,
    pub(super) presets: Option<crate::access::presets::PresetEntity>,
}

/// DB and runtime observations ordered with this service's publication queue.
pub(super) struct Observation<T> {
    pub(super) value: T,
    pub(super) applied_revision: Option<u64>,
    pub(super) running: bool,
}

pub(super) struct Status {
    pub(super) saved_revision: u64,
    pub(super) applied_revision: Option<u64>,
    pub(super) durable_applied_revision: Option<u64>,
    pub(super) running: bool,
    pub(super) user_count: u32,
    pub(super) credential_count: u32,
}

/// Only first acceptance can carry entities and a one-time target-issued secret.
/// Replayed and rejected receipts are metadata, never reconstructed secrets.
pub(super) struct CommandResult {
    pub(super) receipt: store::Receipt,
    pub(super) user: Option<UserView>,
    pub(super) credential: Option<CredentialView>,
    pub(super) secret: Option<Zeroizing<String>>,
    /// Only first acceptance carries the exact routing entity from that commit.
    /// Replay recovers its durable reference, never a reconstructed live entity.
    pub(super) routing: Option<crate::access::routing::RoutingEntity>,
    pub(super) presets: Option<crate::access::presets::PresetEntity>,
    pub(super) replayed: bool,
}

/// The same coordinator is given to both identity domains; neither transport
/// constructs a second reader, writer queue or live/applied state.
pub(super) struct Coordinator {
    directory: PathBuf,
    reader: Reader,
    traffic_restoration: store::traffic::Status,
    /// Loaded once before listeners/collectors start. Policy revisions select
    /// built-in presets; they cannot replace the privileged kernel owner.
    preset_config: OnceLock<crate::ebpf::Config>,
    /// Restart-owned public endpoint claims; these never enter policy revisions
    /// or select a route, TLS identity or network request destination.
    endpoints: OnceLock<Vec<super::proxy::ListenerView>>,
    endpoint_inventory: OnceLock<store::endpoints::Inventory>,
    /// A cold, process-local control handle, installed only after actual socket
    /// readiness. It never owns the forwarding runtime or its author guard.
    runtime: OnceLock<super::proxy::Lifecycle>,
    service: OnceLock<(String, super::proxy::service::Control)>,
    write_work: Arc<Semaphore>,
    /// Bound queued observations and mutations separately from the one worker.
    /// Pending callers own this permit until admission, timeout or cancellation.
    write_pending: Arc<Semaphore>,
    read_work: Arc<Semaphore>,
    /// Two admitted deliveries, one traffic checkpoint and one alert collector
    /// are the only internal wait owners. This bounds queued futures, not workers;
    /// adding another owner requires reviewing this budget and its lifecycle.
    read_pending: Arc<Semaphore>,
    running: AtomicBool,
    #[cfg(feature = "witness-journal")]
    source: Option<store::journal::worker::Worker>,
    _author: Arc<store::Guard>,
}

/// Drop precedes the update gate and writer permit because it is constructed
/// last inside the worker. Unknown commit failures and unwinds fail closed.
struct Publication<'a> {
    reader: &'a Reader,
    uncertain: bool,
}

impl Drop for Publication<'_> {
    fn drop(&mut self) {
        if self.uncertain {
            self.reader.fail_closed();
        }
    }
}

impl Publication<'_> {
    fn reject(&mut self, error: &io::Error) {
        // SQLite I/O errors are not proof of rollback. Ordinary pre-commit
        // rejections leave the old reader valid; uncertain failures do not.
        // https://www.sqlite.org/lang_transaction.html#response_to_errors_within_a_transaction
        self.uncertain = !matches!(
            error.kind(),
            io::ErrorKind::InvalidInput
                | io::ErrorKind::NotFound
                | io::ErrorKind::AlreadyExists
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::WouldBlock
        );
    }
}

enum Authority {
    Local(String),
    Remote(store::RemoteAuthorization),
}

impl Authority {
    fn snapshot(
        &self,
        directory: &Path,
        assertion: Option<&admission::Assertion>,
    ) -> io::Result<admission::Snapshot> {
        match self {
            Self::Local(administrator) => {
                admission::local_runtime_snapshot(directory, administrator, assertion)
            }
            Self::Remote(authorization) => {
                let saved = admission::remote_snapshot(directory, authorization)?;
                if let Some(assertion) = assertion {
                    if saved.node_id != assertion.node_id {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            store::ControlError::TargetMismatch,
                        ));
                    }
                    if saved.ownership.epoch != assertion.epoch {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            store::ControlError::EpochConflict,
                        ));
                    }
                }
                Ok(saved)
            }
        }
    }
}

impl Coordinator {
    pub(super) fn new(
        directory: PathBuf,
        policy: PolicyData,
        author: Arc<store::Guard>,
    ) -> io::Result<Arc<Self>> {
        let restored = store::traffic::restore(&directory)?;
        let traffic = crate::access::traffic::Registry::with_pools(
            restored.credential_seeds,
            restored.pool_seeds,
        )?;
        Ok(Arc::new(Self::from_reader(
            directory,
            Reader::with_traffic(policy, traffic)?,
            restored.status,
            author,
        )))
    }

    fn from_reader(
        directory: PathBuf,
        reader: Reader,
        traffic_restoration: store::traffic::Status,
        author: Arc<store::Guard>,
    ) -> Self {
        Self {
            directory,
            reader,
            traffic_restoration,
            preset_config: OnceLock::new(),
            endpoints: OnceLock::new(),
            endpoint_inventory: OnceLock::new(),
            runtime: OnceLock::new(),
            service: OnceLock::new(),
            write_work: Arc::new(Semaphore::new(1)),
            write_pending: Arc::new(Semaphore::new(MAX_PENDING_WRITERS)),
            read_work: Arc::new(Semaphore::new(2)),
            read_pending: Arc::new(Semaphore::new(MAX_PENDING_READERS)),
            running: AtomicBool::new(false),
            #[cfg(feature = "witness-journal")]
            source: None,
            _author: author,
        }
    }

    /// Unbound kernel fixtures only. Production construction requires the
    /// complete captured inputs and accepted reference, not independent args.
    #[cfg(all(test, feature = "witness-journal"))]
    pub(in crate::manage) async fn new_source(
        directory: PathBuf,
        author: Arc<store::Guard>,
        enrollment: super::witness::Enrollment,
        endpoint: String,
        identity: super::tls::NodeIdentity,
    ) -> io::Result<Arc<Self>> {
        let (worker, ready) = store::journal::worker::Worker::start(
            directory.clone(),
            author.clone(),
            enrollment,
            endpoint,
            identity,
        )
        .await?;
        let mut coordinator = Self::from_reader(directory, ready.reader, ready.restoration, author);
        coordinator.source = Some(worker);
        Ok(Arc::new(coordinator))
    }

    /// Consume this directory's registered capture, then compare its exact SQL
    /// reference under the worker's author/update guards before loading policy.
    /// The original identity, witness selection and returned runtime inputs are
    /// used without reopening source paths. No reference is accepted by hash
    /// alone: current witness confirmation is still required on that worker.
    ///
    /// This is an internal preparation step, not public Source admission or an
    /// activation/fencing proof. The caller retains all returned inputs and
    /// completes binary/host/issuer/egress gates before any listener can start.
    /// Cancelled startup retains its author through real blocking/thread cleanup.
    #[cfg(feature = "witness-journal")]
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Public Source startup awaits complete activation gates"
        )
    )]
    pub(in crate::manage) async fn new_registered_source(
        directory: PathBuf,
        author: Arc<store::Guard>,
        registered: super::snapshot::Registered,
    ) -> io::Result<(Arc<Self>, super::snapshot::inputs::Prepared)> {
        let (worker, ready, inputs) = store::journal::worker::Worker::start_registered(
            directory.clone(),
            author.clone(),
            registered,
        )
        .await?;
        let mut coordinator = Self::from_reader(directory, ready.reader, ready.restoration, author);
        coordinator.source = Some(worker);
        Ok((Arc::new(coordinator), inputs))
    }

    /// Read metadata only for this capture and actual node identity. A fresh Source turn
    /// checks original guards/floors without an intent or sequence advance;
    /// cancellation retains its writer permit and author until real completion.
    /// An unmatched coordinator/directory/key/reference never falls back to
    /// Native. This permits no pending recovery, migration or proxy activation.
    #[cfg(feature = "witness-journal")]
    pub(in crate::manage) async fn source_startup(
        self: &Arc<Self>,
        directory: PathBuf,
        reference: store::journal::configuration::Reference,
        key_sha256: [u8; 32],
    ) -> io::Result<store::Overview> {
        let denied = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "matching registered node coordinator required",
            )
        };
        let source = self
            .source
            .as_ref()
            .filter(|s| s.configured_for(reference, key_sha256))
            .ok_or_else(denied)?;
        let permit = self.writer().await?;
        let author = self._author.clone();
        source
            .write(
                permit,
                move |_| {
                    author.ensure(&directory)?;
                    if store::recovery::diagnostic_startup(&directory)?
                        .is_some_and(|expected| expected != key_sha256)
                    {
                        return Err(denied());
                    }
                    store::inspect(&directory)
                },
                || false,
            )
            .await
            .map(|(overview, _)| overview)
    }

    /// Explicitly resolve only the retained source operation. This recovers no
    /// one-time result. A native Coordinator cannot use this operation.
    #[cfg(feature = "witness-journal")]
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Source reconciliation has no operator route until startup admission is complete"
        )
    )]
    pub(in crate::manage) async fn reconcile_source(self: &Arc<Self>) -> io::Result<()> {
        let source = self.source.as_ref().ok_or_else(worker_unavailable)?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        source
            .reconcile(permit, move || coordinator.running.load(Ordering::Acquire))
            .await
    }

    /// Close source handoff after listeners/collectors stop, then keep Tokio
    /// alive until accepted writes release their SQL and guards. Native nodes
    /// have no persistent source thread. Repeated/cancelled waits are safe.
    pub(in crate::manage) async fn shutdown_writer(&self) -> io::Result<()> {
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            self.write_work.close();
            return source.shutdown().await;
        }
        Ok(())
    }

    pub(super) fn reader(&self) -> Reader {
        self.reader.clone()
    }

    /// Install the already-loaded backend before sharing startup state. A
    /// second installation fails rather than replacing live egress programs.
    pub(super) fn configure_presets(&self, config: crate::ebpf::Config) -> io::Result<()> {
        self.preset_config.set(config).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "preset backend already configured",
            )
        })
    }

    /// Availability belongs to this process's actual backend, not its OS name
    /// or a peer's cached identity document. Missing startup configuration is
    /// reported unavailable, never as a ready/native fallback.
    pub(super) fn preset_config(&self) -> Option<&crate::ebpf::Config> {
        self.preset_config.get()
    }

    /// Install validated startup metadata once, before listener readiness. A
    /// later policy update cannot replace the process's immutable endpoints.
    pub(super) fn configure_endpoints(
        &self,
        listeners: Vec<super::proxy::ListenerView>,
    ) -> io::Result<()> {
        self.endpoints.set(listeners).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "proxy endpoints already configured",
            )
        })
    }

    /// Configuration is not reachability: only activation after socket readiness
    /// sets running, and shutdown clears it without discarding the configuration.
    pub(super) fn endpoints(&self, node_id: &str) -> io::Result<super::proxy::EndpointCatalog> {
        if let Some((configured_node, control)) = self.service.get() {
            if configured_node != node_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "service endpoint node mismatch",
                ));
            }
            let view = control.snapshot()?;
            return Ok(super::proxy::EndpointCatalog {
                node_id: node_id.to_owned(),
                proxy_running: self.running.load(Ordering::Acquire)
                    && view.phase == super::proxy::service::Phase::Running,
                listeners: view.endpoints,
            });
        }
        Ok(super::proxy::EndpointCatalog {
            node_id: node_id.to_owned(),
            proxy_running: self.running.load(Ordering::Acquire),
            listeners: self.endpoints.get().cloned().unwrap_or_default(),
        })
    }

    /// Synchronize only descriptive startup metadata before exposing APIs. Old
    /// schemas retain their v1 read-only directory until an explicit migration.
    pub(super) async fn configure_endpoint_settings(
        self: &Arc<Self>,
        node_id: &str,
    ) -> io::Result<()> {
        let inventory = store::endpoints::Inventory::from_views(
            node_id,
            self.endpoints.get().map(Vec::as_slice).unwrap_or_default(),
        )?;
        self.sync_endpoint_inventory(inventory.clone()).await?;
        self.endpoint_inventory.set(inventory).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "endpoint startup inventory already configured",
            )
        })
    }

    /// Persist the supplied startup digest before publishing it in RAM. The
    /// source path uses its held transaction; an unchanged digest is read-only.
    async fn sync_endpoint_inventory(
        self: &Arc<Self>,
        inventory: store::endpoints::Inventory,
    ) -> io::Result<()> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| store::endpoints::sync_inventory(tx, &inventory),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|_| ());
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if store::inspect(&coordinator.directory)?.schema_version >= 15 {
                let gate = store::update_lock(&coordinator.directory)?;
                store::endpoints::configure(&coordinator.directory, &gate, &inventory)?;
            }
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(super) fn endpoint_inventory(&self) -> io::Result<store::endpoints::Inventory> {
        if let Some((node, control)) = self.service.get() {
            let view = control.snapshot()?;
            return store::endpoints::Inventory::from_views(node, &view.endpoints);
        }
        self.endpoint_inventory.get().cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "endpoint startup inventory is unavailable",
            )
        })
    }

    pub(super) async fn endpoint_settings(
        self: &Arc<Self>,
        node_id: &str,
    ) -> io::Result<super::proxy::SettingsCatalog> {
        let inventory = self.endpoint_inventory()?;
        let state = self.read(store::endpoints::read).await?;
        super::proxy::SettingsCatalog::new(
            node_id,
            self.running.load(Ordering::Acquire),
            &inventory,
            state,
        )
    }

    pub(super) async fn effective_endpoints(
        self: &Arc<Self>,
        node_id: &str,
    ) -> io::Result<super::proxy::EndpointCatalog> {
        if self.endpoint_inventory.get().is_none() && self.service.get().is_none() {
            return self.endpoints(node_id);
        }
        match self.endpoint_settings(node_id).await {
            Ok(settings) => Ok(settings.legacy()),
            Err(error)
                if error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<store::endpoints::Error>())
                    .is_some_and(|e| matches!(e, store::endpoints::Error::UpgradeRequired)) =>
            {
                self.endpoints(node_id)
            }
            Err(error) => Err(error),
        }
    }

    /// Metadata work owns the ordinary writer/author/update gates through commit
    /// even if HTTP is cancelled. It does not publish another policy revision.
    /// A witnessed source conservatively suspends admission on an unknown
    /// witness outcome until explicit reconciliation of that original mutation.
    pub(super) async fn endpoint_change(
        self: &Arc<Self>,
        administrator: String,
        expected_revision: u64,
        generation: String,
        change: store::endpoints::Change,
    ) -> io::Result<store::endpoints::State> {
        let inventory = self.endpoint_inventory()?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| {
                        store::endpoints::change_local_in(
                            tx,
                            &administrator,
                            expected_revision,
                            &generation,
                            &inventory,
                            &change,
                        )
                    },
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(state, _)| state);
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            store::endpoints::change_local(
                &coordinator.directory,
                &gate,
                &administrator,
                expected_revision,
                &generation,
                &inventory,
                &change,
            )
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(super) async fn endpoint_command(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        command: store::endpoint_control::Command,
    ) -> io::Result<store::endpoint_control::Outcome> {
        let inventory = self.endpoint_inventory()?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| {
                        store::endpoint_control::apply_in(tx, &authorization, &inventory, command)
                    },
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(outcome, _)| outcome);
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            store::endpoint_control::apply(
                &coordinator.directory,
                &gate,
                &authorization,
                &inventory,
                command,
            )
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// The metadata read in the same restoration transaction as the live seed.
    /// Startup must not open a run against a newer cursor with older counters.
    pub(super) fn traffic_restoration(&self) -> store::traffic::Status {
        self.traffic_restoration.clone()
    }

    /// Admit at most eight waiters in the existing writer semaphore's FIFO order.
    /// A full queue or 250 ms wait returns the ordinary busy error before any
    /// worker is spawned. Dropping this future cancels its queue position; once
    /// admitted, the returned permit belongs to the worker through publication.
    /// This deadline bounds admission only; it does not interrupt an admitted
    /// worker or limit the duration of its transaction.
    async fn writer(&self) -> io::Result<OwnedSemaphorePermit> {
        let pending = self
            .write_pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let permit = tokio::time::timeout(WRITER_WAIT, self.write_work.clone().acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| busy())?;
        drop(pending);
        Ok(permit)
    }

    /// Native fault/replay fixtures retain the original admitted transaction
    /// boundary. Production journals use their typed Native/Source writer.
    #[cfg(test)]
    pub(super) async fn observations_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path, &store::UpdateGuard) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.native_write_staged(operation)
            .await
            .map_err(|failure| failure.error)
    }

    /// Called after all managed listeners bind. A durable historical receipt
    /// alone cannot mark this process as running. Startup uses the writer/gate
    /// ordering too, so live peer revocation cannot race its receipt window.
    pub(super) async fn activate(self: &Arc<Self>) -> io::Result<()> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .activate(permit, move || {
                    coordinator.running.store(true, Ordering::Release);
                })
                .await;
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _gate = store::update_lock(&coordinator.directory)?;
            let mut publication = Publication {
                reader: &coordinator.reader,
                uncertain: true,
            };
            store::record_applied(&coordinator.directory, coordinator.reader.revision()?)?;
            coordinator.running.store(true, Ordering::Release);
            publication.uncertain = false;
            Ok(())
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(super) fn deactivate(&self) {
        self.running.store(false, Ordering::Release);
    }

    /// Observe process-local admission without acquiring the policy writer.
    /// This is not a coherent DB/live revision sample; callers needing one use
    /// `observe`, while cold-path alerts can retain uncertainty across changes.
    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Stable DB/live sampling; the closure's blocking work owns the permit.
    pub(super) async fn observe<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> io::Result<Observation<T>> {
        let coordinator = self.clone();
        self.metadata_write(move |directory| {
            let value = operation(directory)?;
            let running = coordinator.running.load(Ordering::Acquire);
            Ok(Observation {
                value,
                running,
                applied_revision: if running {
                    coordinator.reader.revision().ok()
                } else {
                    None
                },
            })
        })
        .await
    }

    /// Serialize non-policy store mutations with policy/checkpoint writers.
    /// The closure acquires its own cross-process update gate and transaction;
    /// do not call a policy publisher or await network work from this closure.
    /// Admission uses the same eight-waiter/250 ms FIFO. Cancellation before
    /// admission submits nothing; afterward the real worker retains this slot
    /// and the process author until its transaction ends, even on reply loss.
    /// Errors stay unchanged and never invalidate the unrelated policy Reader.
    pub(super) async fn metadata_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(&coordinator.directory)
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    #[cfg(feature = "witness-journal")]
    pub(super) fn has_source_writer(&self) -> bool {
        self.source.is_some()
    }

    /// Revalidate the caller's login fence immediately before the source SQL
    /// comparison. Rejected authority is a read-only result. Once accepted, the
    /// original worker owns writer admission through confirmation; success is
    /// never inferred from local SQL alone. The API retains its password-work
    /// permit and completes its separate session fence after this returns.
    #[cfg(feature = "witness-journal")]
    pub(super) async fn source_password_change<E: Send + 'static>(
        self: &Arc<Self>,
        change: store::administrators::PasswordChange,
        begin: impl FnOnce() -> Result<(), E> + Send + 'static,
    ) -> io::Result<Result<store::administrators::PasswordChangeOutcome, E>> {
        let source = self.source.as_ref().ok_or_else(worker_unavailable)?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        let (result, _) = source
            .write(
                permit,
                move |tx| {
                    if let Err(error) = begin() {
                        return Ok(Err(error));
                    }
                    store::administrators::apply_password_change_in(tx, &change).map(Ok)
                },
                move || coordinator.running.load(Ordering::Acquire),
            )
            .await?;
        Ok(result.map(|changed| {
            if changed {
                store::administrators::PasswordChangeOutcome::Committed
            } else {
                store::administrators::PasswordChangeOutcome::Conflict
            }
        }))
    }

    pub(super) async fn status(self: &Arc<Self>) -> io::Result<Status> {
        let observed = self.observe(store::policy_status).await?;
        Ok(Status {
            saved_revision: observed.value.revision,
            applied_revision: observed.applied_revision,
            durable_applied_revision: observed.value.applied_revision,
            running: observed.running,
            user_count: observed.value.user_count,
            credential_count: observed.value.credential_count,
        })
    }

    /// Bounded blocking store work. Policy mutations must use the writer
    /// methods, which retain the update gate through publication and receipts.
    /// Target metadata/outbox mutations use `targets_write`, even when they
    /// originate from a remote GET. Otherwise their update gate bypasses the
    /// writer FIFO and can spuriously reject an already-admitted policy edit.
    pub(super) async fn read<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.read_staged(operation)
            .await
            .map_err(|failure| failure.error)
    }

    /// The same fail-fast read budget, with a local failure stage. No extra
    /// worker or queue is created; callers must not expose the inner message.
    pub(super) async fn read_staged<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> Result<T, ReadFailure> {
        self.read_with_admission_staged(ReadAdmission::Immediate, operation)
            .await
    }

    /// Select admission explicitly for one local operation. Internal callers
    /// may wait at most 250 ms for a slot; this does not extend their enclosing
    /// deadlines or interrupt a worker that has already started. The original
    /// operation error and its typed source are returned unchanged.
    pub(super) async fn read_with_admission<T: Send + 'static>(
        self: &Arc<Self>,
        admission: ReadAdmission,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.read_with_admission_staged(admission, operation)
            .await
            .map_err(|failure| failure.error)
    }

    /// The selected admission policy with local failure diagnostics. Waiting
    /// cancellation releases its queue budget and FIFO position without spawning
    /// work. Once admitted, the blocking worker owns its slot and process author.
    pub(super) async fn read_with_admission_staged<T: Send + 'static>(
        self: &Arc<Self>,
        admission: ReadAdmission,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> Result<T, ReadFailure> {
        let permit = self
            .read_permit(admission)
            .await
            .map_err(|error| ReadFailure {
                stage: ReadStage::Admission,
                error,
            })?;
        self.read_with_permit(permit, operation).await
    }

    async fn read_permit(&self, admission: ReadAdmission) -> io::Result<OwnedSemaphorePermit> {
        if admission == ReadAdmission::Immediate {
            return self
                .read_work
                .clone()
                .try_acquire_owned()
                .map_err(|_| busy());
        }
        let pending = self
            .read_pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let permit =
            tokio::time::timeout(INTERNAL_READ_WAIT, self.read_work.clone().acquire_owned())
                .await
                .map_err(|_| busy())?
                .map_err(|_| busy())?;
        drop(pending);
        Ok(permit)
    }

    /// The single-flight checkpoint shares internal admission with deliveries
    /// and the alert collector, rather than opening another wait queue. Its
    /// original 250 ms admission deadline and two-worker limit are unchanged.
    pub(super) async fn traffic_sample<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.read_with_admission(ReadAdmission::Internal, move |_| operation())
            .await
    }

    /// An admitted worker keeps its slot and process author even if the caller
    /// stops awaiting it. Queueing never transfers a permit to a detached task.
    async fn read_with_permit<T: Send + 'static>(
        self: &Arc<Self>,
        permit: OwnedSemaphorePermit,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> Result<T, ReadFailure> {
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(&coordinator.directory)
        })
        .await
        .map_err(|_| ReadFailure {
            stage: ReadStage::Worker,
            error: worker_unavailable(),
        })?
        .map_err(|error| ReadFailure {
            stage: ReadStage::Operation,
            error,
        })
    }

    /// Offline/browser writes and remote writes share the exact same reader
    /// publication and receipt queue; no HTTP identity enters the store here.
    pub(super) async fn change(
        self: &Arc<Self>,
        administrator: String,
        expected_revision: u64,
        change: PolicyChange,
    ) -> io::Result<Change> {
        self.change_asserted(administrator, expected_revision, change, None)
            .await
    }

    async fn change_asserted(
        self: &Arc<Self>,
        administrator: String,
        expected_revision: u64,
        change: PolicyChange,
        assertion: Option<store::admission::Assertion>,
    ) -> io::Result<Change> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let restart_required =
                matches!(&change, PolicyChange::SetAdmission { accepting: true })
                    && !self.runtime_can_resume()?;
            let directory = self.directory.clone();
            let (result, running) = source
                .write(
                    permit,
                    move |tx| {
                        if restart_required {
                            store::admission::local_runtime_snapshot(
                                &directory,
                                &administrator,
                                assertion.as_ref(),
                            )?;
                            return Err(super::drain::Error::RestartRequired.error());
                        }
                        store::apply_local_policy_in(
                            tx,
                            &administrator,
                            expected_revision,
                            change,
                            assertion.as_ref(),
                        )
                    },
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await?;
            let store::ChangeResult {
                policy,
                user,
                credential,
                secret,
                routing,
                presets,
            } = result;
            return Ok(Change {
                revision: policy.revision,
                running,
                user,
                credential,
                secret,
                routing,
                presets,
            });
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            if matches!(&change, PolicyChange::SetAdmission { accepting: true })
                && !coordinator.runtime_can_resume()?
            {
                store::admission::local_runtime_snapshot(
                    &coordinator.directory,
                    &administrator,
                    assertion.as_ref(),
                )?;
                return Err(super::drain::Error::RestartRequired.error());
            }
            let mut publication = Publication {
                reader: &coordinator.reader,
                uncertain: true,
            };
            let result = match assertion {
                Some(assertion) => store::apply_policy_asserted(
                    &coordinator.directory,
                    &administrator,
                    expected_revision,
                    change,
                    &gate,
                    &assertion,
                ),
                None => store::apply_policy(
                    &coordinator.directory,
                    &administrator,
                    expected_revision,
                    change,
                    &gate,
                ),
            };
            let store::ChangeResult {
                policy,
                user,
                credential,
                secret,
                routing,
                presets,
            } = match result {
                Ok(result) => result,
                Err(error) => {
                    publication.reject(&error);
                    return Err(error);
                }
            };
            let revision = policy.revision;
            coordinator
                .reader
                .publish(policy)
                .map_err(|_| io::Error::other(Error::PublicationFailed))?;
            let running = coordinator.running.load(Ordering::Acquire);
            if running {
                store::record_applied(&coordinator.directory, revision)?;
            }
            publication.uncertain = false;
            Ok(Change {
                revision,
                running,
                user,
                credential,
                secret,
                routing,
                presets,
            })
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(super) async fn ownership(self: &Arc<Self>) -> io::Result<store::Ownership> {
        Ok(self.observe(store::ownership).await?.value)
    }

    /// An explicit local administrator may change the owner, not silently edit
    /// a remotely managed resource. Epoch CAS and actor checks belong to SQL.
    pub(super) async fn set_owner(
        self: &Arc<Self>,
        administrator: String,
        expected_epoch: u64,
        controller: Option<String>,
    ) -> io::Result<store::Ownership> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| {
                        store::set_owner_in(
                            tx,
                            &administrator,
                            expected_epoch,
                            controller.as_deref(),
                        )
                    },
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(owner, _)| owner);
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            let mut publication = Publication {
                reader: &coordinator.reader,
                uncertain: true,
            };
            match store::set_owner(
                &coordinator.directory,
                &gate,
                &administrator,
                expected_epoch,
                controller.as_deref(),
            ) {
                Ok(owner) => {
                    publication.uncertain = false;
                    Ok(owner)
                }
                Err(error) => {
                    publication.reject(&error);
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// The TLS identity is supplied by the node transport; JSON cannot create
    /// it. SQL checks that identity, owner/epoch, sequence, digest and CAS in its
    /// single immediate transaction while this worker retains the update gate.
    pub(super) async fn command(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        command: store::Command,
    ) -> io::Result<CommandResult> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let can_resume = self.runtime_can_resume()?;
            let (outcome, running) = source
                .write(
                    permit,
                    move |tx| store::apply_command_in(tx, &authorization, command, can_resume),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await?;
            return Ok(match outcome {
                store::CommandOutcome::Accepted {
                    change,
                    mut receipt,
                } => {
                    let store::ChangeResult {
                        user,
                        credential,
                        secret,
                        routing,
                        presets,
                        ..
                    } = *change;
                    if running {
                        receipt.status = store::ReceiptStatus::Applied;
                    }
                    CommandResult {
                        receipt,
                        user,
                        credential,
                        secret,
                        routing,
                        presets,
                        replayed: false,
                    }
                }
                store::CommandOutcome::Replayed(receipt) => CommandResult {
                    receipt,
                    user: None,
                    credential: None,
                    secret: None,
                    routing: None,
                    presets: None,
                    replayed: true,
                },
                store::CommandOutcome::Rejected(receipt) => CommandResult {
                    receipt,
                    user: None,
                    credential: None,
                    secret: None,
                    routing: None,
                    presets: None,
                    replayed: false,
                },
            });
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            let can_resume = coordinator.runtime_can_resume()?;
            let mut publication = Publication {
                reader: &coordinator.reader,
                uncertain: true,
            };
            let outcome = match store::apply_command_with_admission(
                &coordinator.directory,
                &gate,
                &authorization,
                command,
                can_resume,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    publication.reject(&error);
                    return Err(error);
                }
            };
            match outcome {
                store::CommandOutcome::Accepted {
                    change,
                    mut receipt,
                } => {
                    let store::ChangeResult {
                        policy,
                        user,
                        credential,
                        secret,
                        routing,
                        presets,
                    } = *change;
                    let revision = policy.revision;
                    coordinator
                        .reader
                        .publish(policy)
                        .map_err(|_| io::Error::other(Error::PublicationFailed))?;
                    if coordinator.running.load(Ordering::Acquire) {
                        store::record_applied(&coordinator.directory, revision)?;
                        store::mark_command_applied(
                            &coordinator.directory,
                            &gate,
                            receipt.epoch,
                            receipt.command_id,
                            revision,
                        )?;
                        receipt.status = store::ReceiptStatus::Applied;
                    }
                    publication.uncertain = false;
                    Ok(CommandResult {
                        receipt,
                        user,
                        credential,
                        secret,
                        routing,
                        presets,
                        replayed: false,
                    })
                }
                store::CommandOutcome::Replayed(receipt) => {
                    publication.uncertain = false;
                    Ok(CommandResult {
                        receipt,
                        user: None,
                        credential: None,
                        secret: None,
                        routing: None,
                        presets: None,
                        replayed: true,
                    })
                }
                store::CommandOutcome::Rejected(receipt) => {
                    publication.uncertain = false;
                    Ok(CommandResult {
                        receipt,
                        user: None,
                        credential: None,
                        secret: None,
                        routing: None,
                        presets: None,
                        replayed: false,
                    })
                }
            }
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    #[cfg(test)]
    pub(super) fn write_work(&self) -> Arc<Semaphore> {
        self.write_work.clone()
    }

    /// Install only the actual ready runtime, once. The synchronous runner keeps
    /// sole ownership of Runtime/author until final process cleanup.
    pub(in crate::manage) fn configure_runtime(&self, runtime: proxy::Lifecycle) -> io::Result<()> {
        if self.service().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "proxy runtime has a managed owner",
            ));
        }
        self.runtime.set(runtime).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "proxy runtime already configured",
            )
        })
    }

    /// A stopped listener cannot be resumed by publishing accepting=true. An
    /// API-only node can still save the policy for its next explicit startup.
    fn runtime_can_resume(&self) -> io::Result<bool> {
        if let Some(service) = self.service() {
            let view = service.snapshot()?;
            if view.phase != proxy::service::Phase::Running {
                return Ok(false);
            }
        }
        self.current_runtime()?
            .as_ref()
            .map(|runtime| {
                runtime
                    .snapshot()
                    .map(|view| view.phase == proxy::Phase::Serving)
            })
            .unwrap_or(Ok(true))
    }

    /// Cold local collection only: inspect the installed runtime without SQL,
    /// queue admission or network work. A poisoned snapshot remains an error,
    /// distinct from a node that has no configured forwarding runtime.
    pub(in crate::manage) fn runtime_observation(&self) -> io::Result<Option<proxy::View>> {
        self.current_runtime()?
            .as_ref()
            .map(proxy::Lifecycle::snapshot)
            .transpose()
    }

    fn current_runtime(&self) -> io::Result<Option<proxy::Lifecycle>> {
        match self.service() {
            Some(service) => Ok(service.snapshot()?.runtime),
            None => Ok(self.runtime.get().cloned()),
        }
    }

    fn runtime_view(&self, saved: admission::Snapshot) -> io::Result<drain::Status> {
        let view = self.runtime_observation()?;
        let active = view
            .as_ref()
            .and_then(|_| self.reader.admission().ok())
            .filter(|live| {
                live.revision == saved.saved_revision && live.accepting == saved.accepting
            })
            .map(|live| live.active_operations);
        let value = drain::Status::new(saved, view, active);
        value.validate(&value.node_id)?;
        Ok(value)
    }

    /// Observe current non-secret facts, or only the exact retained request.
    /// Replaced runtime/operation identities are never silently rebound.
    pub(in crate::manage) async fn runtime_status(
        self: &Arc<Self>,
        administrator: String,
        exact: Option<(String, String)>,
    ) -> io::Result<drain::Status> {
        self.runtime_status_as(Authority::Local(administrator), exact)
            .await
    }

    /// A verified peer must still be the current owner for every observation,
    /// including exact requests originally issued before a permission change.
    pub(in crate::manage) async fn remote_runtime_status(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        exact: Option<(String, String)>,
    ) -> io::Result<drain::Status> {
        self.runtime_status_as(Authority::Remote(authorization), exact)
            .await
    }

    async fn runtime_status_as(
        self: &Arc<Self>,
        authority: Authority,
        exact: Option<(String, String)>,
    ) -> io::Result<drain::Status> {
        if exact.as_ref().is_some_and(|(runtime, request)| {
            !store::valid_id(runtime) || !store::valid_id(request)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid proxy runtime identity",
            ));
        }
        let permit = self.writer().await?;
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let saved = authority.snapshot(&coordinator.directory, None)?;
            let value = coordinator.runtime_view(saved)?;
            if let Some((runtime_id, request_id)) = exact {
                let matches = value.runtime.as_ref().is_some_and(|runtime| {
                    runtime.runtime_id == runtime_id
                        && runtime
                            .request
                            .as_ref()
                            .is_some_and(|request| request.request_id == request_id)
                });
                if !matches {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "proxy drain request not found in this runtime",
                    ));
                }
            }
            Ok(value)
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// Accept one already-paused local request. Cancellation of the HTTP wait
    /// does not interrupt this worker or the forwarding supervisor afterwards.
    pub(in crate::manage) async fn request_drain(
        self: &Arc<Self>,
        administrator: String,
        request: drain::Request,
    ) -> io::Result<drain::Status> {
        let actor = proxy::DrainActor::Local {
            administrator_id: administrator.clone(),
        };
        self.request_drain_as(Authority::Local(administrator), actor, request)
            .await
    }

    /// The foreign administrator is an audit claim by the already verified
    /// owner. It is never treated as a local administrator or control grant.
    pub(in crate::manage) async fn request_remote_drain(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        source_administrator: String,
        request: drain::Request,
    ) -> io::Result<drain::Status> {
        if !store::valid_id(&source_administrator) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid proxy runtime actor",
            ));
        }
        let actor = proxy::DrainActor::Remote {
            controller_node_id: authorization.node_id.clone(),
            administrator_id: source_administrator,
        };
        self.request_drain_as(Authority::Remote(authorization), actor, request)
            .await
    }

    async fn request_drain_as(
        self: &Arc<Self>,
        authority: Authority,
        actor: proxy::DrainActor,
        request: drain::Request,
    ) -> io::Result<drain::Status> {
        let (epoch, revision) = request.numbers()?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _gate = store::update_lock(&coordinator.directory)?;
            let saved = authority.snapshot(
                &coordinator.directory,
                Some(&admission::Assertion {
                    node_id: request.expected_node_id.clone(),
                    epoch,
                }),
            )?;
            let runtime = coordinator
                .current_runtime()?
                .ok_or_else(|| drain::Error::Unavailable.error())?;
            let current = runtime.snapshot()?;
            let intent = proxy::DrainIntent {
                node_id: request.expected_node_id,
                request_id: request.request_id,
                epoch,
                revision,
                actor,
            };
            if current.intent.is_none() {
                if current.runtime_id != request.runtime_id {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        proxy::Error::RuntimeChanged,
                    ));
                }
                if saved.saved_revision != revision {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "proxy policy revision changed",
                    ));
                }
                if saved.accepting {
                    return Err(drain::Error::AdmissionNotPaused.error());
                }
                let live = coordinator
                    .reader
                    .admission()
                    .map_err(|_| drain::Error::PolicyUnavailable.error())?;
                if !coordinator.running.load(Ordering::Acquire)
                    || live.revision != revision
                    || live.accepting
                {
                    return Err(drain::Error::PolicyUnavailable.error());
                }
            }
            runtime.request(&request.runtime_id, intent)?;
            // Listener acceptance is no longer advertised as live. The Reader
            // still owns paused policy and the traffic runner keeps sampling.
            coordinator.deactivate();
            coordinator.runtime_view(saved)
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(in crate::manage) fn configure_service(
        &self,
        node_id: String,
        control: proxy::service::Control,
    ) -> io::Result<()> {
        if !store::valid_id(&node_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid service node",
            ));
        }
        if self.runtime.get().is_some() || self.endpoints.get().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "startup-file proxy is already configured",
            ));
        }
        self.service.set((node_id, control)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "managed service is already configured",
            )
        })
    }

    pub(in crate::manage) fn service(&self) -> Option<&proxy::service::Control> {
        self.service.get().map(|(_, control)| control)
    }

    pub(in crate::manage) fn service_directory(&self) -> &Path {
        &self.directory
    }

    /// Native-only gate. Source socket settings have no witnessed activation
    /// contract and are also refused by their changeset classifier.
    pub(in crate::manage) async fn service_writer(
        self: &Arc<Self>,
    ) -> io::Result<OwnedSemaphorePermit> {
        #[cfg(feature = "witness-journal")]
        if self.source.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed service is unavailable for witnessed sources",
            ));
        }
        self.writer().await
    }

    /// Caller owns the Native writer permit and directory-bound update guard,
    /// and has already observed actual bind readiness. On uncertain publication
    /// the Reader fails closed, as in ordinary startup activation.
    pub(in crate::manage) fn service_activate(&self, gate: &store::UpdateGuard) -> io::Result<()> {
        self._author.ensure(&self.directory)?;
        let mut publication = Publication {
            reader: &self.reader,
            uncertain: true,
        };
        store::proxy_service::record_applied(&self.directory, gate, self.reader.revision()?)?;
        self.running.store(true, Ordering::Release);
        publication.uncertain = false;
        Ok(())
    }

    /// Sample saved identity/ownership and the live admission view in writer
    /// order. An unreadable live count is unknown, not zero. This does not wait
    /// for existing operations, flush protocol buffers, or change admission.
    pub(in crate::manage) async fn maintenance(
        self: &Arc<Self>,
        authorization: Option<store::RemoteAuthorization>,
    ) -> io::Result<maintenance::Status> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let saved = match authorization {
                Some(authorization) => {
                    admission::remote_snapshot(&coordinator.directory, &authorization)?
                }
                None => admission::snapshot(&coordinator.directory)?,
            };
            let running = coordinator.running.load(Ordering::Acquire);
            let mut live = running
                .then(|| coordinator.reader.admission().ok())
                .flatten()
                .filter(|live| {
                    live.revision == saved.saved_revision && live.accepting == saved.accepting
                });
            // Deactivation does not take the writer permit. Recheck after the
            // Reader sample so a stopped runtime cannot retain a live count.
            // Activation does take this permit, so it cannot race false->true.
            let running = running && coordinator.running.load(Ordering::Acquire);
            if !running {
                live = None;
            }
            Ok(maintenance::Status {
                node_id: saved.node_id,
                ownership: saved.ownership.into(),
                saved_revision: saved.saved_revision.to_string(),
                durable_applied_revision: saved
                    .durable_applied_revision
                    .map(|value| value.to_string()),
                running,
                saved_accepting: saved.accepting,
                applied_revision: live.as_ref().map(|value| value.revision.to_string()),
                runtime_accepting: live.as_ref().map(|value| value.accepting),
                active_operations: live.map(|value| value.active_operations.to_string()),
            })
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// Apply one administrator-confirmed local intent. Node identity and owner
    /// epoch are asserted in the same transaction as policy CAS and audit. A
    /// cancelled HTTP waiter does not cancel the worker or repeat the mutation.
    pub(in crate::manage) async fn change_admission(
        self: &Arc<Self>,
        administrator: String,
        expected_revision: u64,
        assertion: admission::Assertion,
        accepting: bool,
    ) -> io::Result<Change> {
        self.change_asserted(
            administrator,
            expected_revision,
            PolicyChange::SetAdmission { accepting },
            Some(assertion),
        )
        .await
    }

    /// Persist a server-issued identity before executing a non-secret user edit.
    /// Cancellation leaves the owned worker and its writer/update guards alive;
    /// a reservation itself never changes admission or the runtime Reader.
    pub(in crate::manage) async fn reserve_user_operation(
        self: &Arc<Self>,
        caller: Caller,
        input: Input,
    ) -> io::Result<Operation> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| operations::reserve_in(tx, &caller, &input),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(operation, _)| operation);
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            match &caller {
                Caller::Administrator(id) => {
                    operations::reserve(&coordinator.directory, &gate, id, &input)
                }
                Caller::Automation(_) => {
                    operations::reserve_as(&coordinator.directory, &gate, &caller, &input)
                }
            }
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// Execute an existing, bound operation at most once. Only the first saved
    /// outcome publishes its candidate; terminal replays never reapply a past
    /// policy. Publication failure leaves a queryable durable Saved record, not
    /// a fabricated rejection or a promise that a proxy runtime applied it.
    pub(in crate::manage) async fn execute_user_operation(
        self: &Arc<Self>,
        caller: Caller,
        id: String,
        input: Input,
    ) -> io::Result<Operation> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let (outcome, _) = source
                .write(
                    permit,
                    move |tx| {
                        operations::execute_in(tx, &caller, &id, input).map_err(|error| {
                            if error.policy_uncertain() {
                                io::Error::other(error)
                            } else {
                                error.into_error()
                            }
                        })
                    },
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await?;
            return Ok(match outcome {
                Outcome::Accepted { operation, .. }
                | Outcome::Replayed(operation)
                | Outcome::Rejected(operation) => operation,
            });
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            // An unwind or uncertain commit must fail closed even if the HTTP
            // future was dropped. Known metadata/pre-commit failures clear this
            // guard explicitly and do not invalidate the unchanged Reader.
            let mut publication = Publication {
                reader: &coordinator.reader,
                uncertain: true,
            };
            let executed = match &caller {
                Caller::Administrator(administrator) => {
                    operations::execute(&coordinator.directory, &gate, administrator, &id, input)
                }
                Caller::Automation(_) => {
                    operations::execute_as(&coordinator.directory, &gate, &caller, &id, input)
                }
            };
            let outcome = match executed {
                Ok(outcome) => outcome,
                Err(error) => {
                    publication.uncertain = error.policy_uncertain();
                    return Err(error.into_error());
                }
            };
            let operation = match outcome {
                Outcome::Accepted { change, operation } => {
                    let revision = change.policy.revision;
                    coordinator
                        .reader
                        .publish(change.policy)
                        .map_err(|_| io::Error::other(Error::PublicationFailed))?;
                    if coordinator.running.load(Ordering::Acquire) {
                        store::record_applied(&coordinator.directory, revision)?;
                    }
                    operation
                }
                Outcome::Replayed(operation) | Outcome::Rejected(operation) => operation,
            };
            publication.uncertain = false;
            Ok(operation)
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    /// Ordinary node I/O must not act on outbox/authority rows that are locally
    /// committed but not witness-confirmed. The dedicated Offline witness
    /// transport bypasses this gate so original reconciliation can progress.
    pub(in crate::manage) fn ensure_source_confirmed(&self) -> io::Result<()> {
        #[cfg(feature = "witness-journal")]
        if self.source.is_some() && self.reader.revision().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "source confirmation is pending",
            ));
        }
        Ok(())
    }

    pub(in crate::manage) async fn targets_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::targets::Writer<'_>) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.targets_write_guarded((), operation).await
    }

    /// An accepted operation owns its external peer/delivery guard through the
    /// actual writer, not its cancellable waiter or short SQL callback. Native
    /// retains each original store commit boundary; Source returns only after
    /// exact witness confirmation. No network delivery belongs in this closure.
    pub(in crate::manage) async fn targets_write_guarded<G: Send + 'static, T: Send + 'static>(
        self: &Arc<Self>,
        guard: G,
        operation: impl FnOnce(&mut store::targets::Writer<'_>) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write_guarded(
                    permit,
                    guard,
                    move |tx| operation(&mut store::targets::Writer::Source(tx)),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(value, _)| value);
        }
        tokio::task::spawn_blocking(move || {
            let (_permit, _guard) = (permit, guard);
            operation(&mut store::targets::Writer::Native(&coordinator.directory))
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    pub(in crate::manage) async fn history_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::alerts::history::Writer<'_>) -> io::Result<T>
        + Send
        + 'static,
    ) -> io::Result<T> {
        self.history_write_then(operation, |value| Ok(value)).await
    }

    /// Accepted work retains the original writer admission through transaction,
    /// Source confirmation and RAM publication. A cancelled waiter cannot skip
    /// the continuation; it runs with no borrowed SQL or network work.
    pub(in crate::manage) async fn history_write_then<T: Send + 'static, R: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::alerts::history::Writer<'_>) -> io::Result<T>
        + Send
        + 'static,
        finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
    ) -> io::Result<R> {
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let permit = self.writer().await?;
            let coordinator = self.clone();
            return source
                .history_then(
                    permit,
                    move |tx, checkpoints| {
                        operation(&mut store::alerts::history::Writer::Source { tx, checkpoints })
                    },
                    finish,
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(value, _)| value);
        }
        self.native_write_staged(move |dir, gate| {
            let value = operation(&mut store::alerts::history::Writer::Native(dir, gate))?;
            finish(value)
        })
        .await
        .map_err(|failure| failure.error)
    }

    /// Return configuration metadata or an owned delivery only after the
    /// transaction confirms. Cancellation may lose the returned HTTP permit,
    /// but cannot roll back accepted work or recreate its immutable body.
    pub(in crate::manage) async fn notifications_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::notifications::Writer<'_>) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let permit = self.writer().await?;
            let coordinator = self.clone();
            return source
                .write(
                    permit,
                    move |tx| operation(&mut store::notifications::Writer::Source(tx)),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(value, _)| value);
        }
        self.native_write_staged(move |dir, gate| {
            operation(&mut store::notifications::Writer::Native(dir, gate))
        })
        .await
        .map_err(|failure| failure.error)
    }

    pub(in crate::manage) async fn traffic_write<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::traffic::Writer<'_>) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        self.traffic_write_staged(operation)
            .await
            .map_err(|failure| failure.error)
    }

    /// Absolute checkpoints and imports share the policy writer FIFO. The
    /// operation stages SQL only; collector RAM watermarks must be updated after
    /// this returns. Cancellation cannot cancel an accepted Source transaction.
    /// The Store stage includes witness uncertainty without hiding its source.
    pub(in crate::manage) async fn traffic_write_staged<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut store::traffic::Writer<'_>) -> io::Result<T> + Send + 'static,
    ) -> Result<T, TrafficWriteFailure> {
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            let permit = self.writer().await.map_err(|error| TrafficWriteFailure {
                stage: TrafficWriteStage::Admission,
                error,
            })?;
            let coordinator = self.clone();
            return source
                .write(
                    permit,
                    move |tx| operation(&mut store::traffic::Writer::Source(tx)),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(value, _)| value)
                .map_err(|error| TrafficWriteFailure {
                    stage: TrafficWriteStage::Store,
                    error,
                });
        }
        self.native_write_staged(move |dir, gate| {
            operation(&mut store::traffic::Writer::Native(dir, gate))
        })
        .await
    }

    /// Native cold journals retain their original update gate and per-store
    /// commit boundary. Unconverted journals do not bypass a Source-held gate.
    async fn native_write_staged<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Path, &store::UpdateGuard) -> io::Result<T> + Send + 'static,
    ) -> Result<T, TrafficWriteFailure> {
        let permit = self.writer().await.map_err(|error| TrafficWriteFailure {
            stage: TrafficWriteStage::Admission,
            error,
        })?;
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory).map_err(|error| {
                TrafficWriteFailure {
                    stage: TrafficWriteStage::UpdateGate,
                    error,
                }
            })?;
            operation(&coordinator.directory, &gate).map_err(|error| TrafficWriteFailure {
                stage: TrafficWriteStage::Store,
                error,
            })
        })
        .await
        .map_err(|_| TrafficWriteFailure {
            stage: TrafficWriteStage::Worker,
            error: worker_unavailable(),
        })?
    }

    /// Do not expose a locally committed witness row before this node's own
    /// Source operation is confirmed. Check both sides of the bounded read so a
    /// concurrent commit cannot turn an earlier readiness check into authority.
    pub(in crate::manage) async fn witness_inspect(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        binding: String,
    ) -> io::Result<Record> {
        self.ensure_source_confirmed()?;
        let result = self
            .read(move |dir| store::witness::remote_inspect(dir, &authorization, &binding))
            .await?;
        self.ensure_source_confirmed()?;
        Ok(result)
    }

    /// Preserve original peer/writer/CAS checks and receipt identity. Accepted
    /// Source work survives cancellation and returns only after confirmation;
    /// failed/unknown replies must be reconciled, never retried as new writes.
    pub(in crate::manage) async fn witness_transition(
        self: &Arc<Self>,
        authorization: store::RemoteAuthorization,
        input: Transition,
        confirm: bool,
    ) -> io::Result<Record> {
        let permit = self.writer().await?;
        let coordinator = self.clone();
        #[cfg(feature = "witness-journal")]
        if let Some(source) = &self.source {
            return source
                .write(
                    permit,
                    move |tx| store::witness::transition_in(tx, &authorization, &input, confirm),
                    move || coordinator.running.load(Ordering::Acquire),
                )
                .await
                .map(|(record, _)| record);
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let gate = store::update_lock(&coordinator.directory)?;
            store::witness::transition(
                &coordinator.directory,
                &gate,
                &authorization,
                &input,
                confirm,
            )
        })
        .await
        .map_err(|_| worker_unavailable())?
    }

    #[cfg(feature = "witness-journal")]
    /// Only a trusted caller holding this exact original process-author guard
    /// may submit offline identity work. It must own no live API/session state;
    /// the running check additionally refuses an active managed runtime, but is
    /// not infrastructure fencing or an authorization substitute. No current
    /// HTTP route calls this path. Accepted work and output remain owned through
    /// confirmation even when the waiter is cancelled; output errors cannot undo
    /// confirmed SQL and must not cause one-time secrets to be recreated.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "File-author Source CLI awaits fixed configuration admission"
        )
    )]
    pub(in crate::manage) async fn source_identity_write_then<
        T: Send + 'static,
        R: Send + 'static,
    >(
        self: &Arc<Self>,
        author: Arc<store::Guard>,
        operation: impl FnOnce(&mut store::identities::Writer<'_>) -> io::Result<T> + Send + 'static,
        finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
    ) -> io::Result<R> {
        if !Arc::ptr_eq(&author, &self._author) || self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "offline identity author required",
            ));
        }
        author.ensure(&self.directory)?;
        let source = self.source.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "source identity writer is not configured",
            )
        })?;
        let permit = self.writer().await?;
        let coordinator = self.clone();
        let running = self.clone();
        source
            .write_then(
                permit,
                author,
                move |tx| {
                    if coordinator.running.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "offline identity author required",
                        ));
                    }
                    operation(&mut store::identities::Writer::new(
                        &coordinator.directory,
                        tx,
                    ))
                },
                finish,
                move || running.running.load(Ordering::Acquire),
            )
            .await
            .map(|(value, _)| value)
    }
}

fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "policy coordinator is busy")
}
fn worker_unavailable() -> io::Error {
    io::Error::other(Error::WorkerUnavailable)
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    mod maintenance {
        use super::*;

        #[tokio::test]
        async fn legacy_maintenance_refusal_keeps_the_active_reader_and_database_unchanged()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let database = fixture.directory.join("management.sqlite3");
            let connection = rusqlite::Connection::open(&database).map_err(io::Error::other)?;
            store::recovery::restore_schema_eighteen_for_test(&connection)?;
            drop(connection);
            let overview = store::inspect(&fixture.directory)?;
            assert_eq!(overview.schema_version, 18);
            let coordinator = fixture.coordinator()?;
            coordinator.activate().await?;
            let before = std::fs::read(&database)?;
            let reader = coordinator.reader();
            let admitted = reader.admission()?;
            assert_eq!(
                (
                    admitted.revision,
                    admitted.accepting,
                    admitted.active_operations
                ),
                (1, true, 0)
            );

            let read_error =
                coordinator.maintenance(None).await.err().ok_or_else(|| {
                    io::Error::other("legacy maintenance observation was accepted")
                })?;
            let write_error = coordinator
                .change_admission(
                    fixture.administrator.clone(),
                    1,
                    store::admission::Assertion {
                        node_id: overview.node_id,
                        epoch: 1,
                    },
                    false,
                )
                .await
                .err()
                .ok_or_else(|| io::Error::other("legacy maintenance write was accepted"))?;
            for error in [read_error, write_error] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(
                    error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<store::admission::Error>()),
                    Some(&store::admission::Error::UpgradeRequired)
                );
            }

            // A checked pre-mutation refusal must not take the publication guard's
            // uncertain-commit path and invalidate the still-serving legacy snapshot.
            assert_eq!(reader.revision()?, 1);
            let admitted = reader.admission()?;
            assert_eq!(
                (
                    admitted.revision,
                    admitted.accepting,
                    admitted.active_operations
                ),
                (1, true, 0)
            );
            let status = coordinator.status().await?;
            assert!(status.running);
            assert_eq!(
                (
                    status.saved_revision,
                    status.applied_revision,
                    status.durable_applied_revision
                ),
                (1, Some(1), Some(1))
            );
            assert!(
                std::fs::read(&database)? == before,
                "a definitive refusal changed the fixture database"
            );
            assert!(store::load_policy(&fixture.directory)?.accepting);
            Ok(())
        }
    }
    mod read_admission {
        use std::{
            sync::{
                atomic::{AtomicBool, Ordering},
                mpsc,
            },
            thread,
            time::Instant,
        };

        use tokio::{sync::oneshot, time::timeout};

        use super::*;

        const WAIT: Duration = Duration::from_secs(10);

        #[tokio::test]
        async fn internal_read_waiters_are_bounded_cancel_safe_and_fifo() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let first = policy.read_permit(ReadAdmission::Immediate).await?;
            let second = policy.read_permit(ReadAdmission::Immediate).await?;
            let mut waiters = (0..MAX_PENDING_READERS)
                .map(|_| Box::pin(policy.read_permit(ReadAdmission::Internal)))
                .collect::<Vec<_>>();
            for waiter in &mut waiters {
                assert!(futures_util::poll!(waiter).is_pending());
            }
            assert_eq!(policy.read_pending.available_permits(), 0);

            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let mut overflow = Box::pin(policy.read_with_admission_staged(
                ReadAdmission::Internal,
                move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(())
                },
            ));
            let Poll::Ready(Err(failure)) = futures_util::poll!(&mut overflow) else {
                panic!("a full internal queue must reject without waiting");
            };
            assert_eq!(failure.stage, ReadStage::Admission);
            assert_eq!(failure.error.kind(), io::ErrorKind::WouldBlock);
            assert!(!called.load(Ordering::Acquire));
            // Checkpoints use this same pending budget, not a fifth reservation path.
            let sample = policy.traffic_sample(|| Ok(())).await.unwrap_err();
            assert_eq!(sample.kind(), io::ErrorKind::WouldBlock);
            let immediate = policy.read_staged(|_| Ok(())).await.unwrap_err();
            assert_eq!(immediate.stage, ReadStage::Admission);
            assert_eq!(immediate.error.kind(), io::ErrorKind::WouldBlock);

            drop(waiters.remove(0));
            assert_eq!(policy.read_pending.available_permits(), 1);
            let mut replacement = Box::pin(policy.read_permit(ReadAdmission::Internal));
            assert!(futures_util::poll!(&mut replacement).is_pending());
            assert_eq!(policy.read_pending.available_permits(), 0);
            drop(first);

            // One slot remains occupied throughout: every release must go to the oldest
            // surviving reservation, not a replacement or a fresh immediate request.
            for waiter in &mut waiters {
                assert!(futures_util::poll!(&mut replacement).is_pending());
                assert!(policy.read_permit(ReadAdmission::Immediate).await.is_err());
                let Poll::Ready(permit) = futures_util::poll!(waiter) else {
                    panic!("the oldest read waiter must own the next slot");
                };
                let permit = permit?;
                assert_eq!(policy.read_work.available_permits(), 0);
                drop(permit);
            }
            let permit = replacement.await?;
            assert_eq!(policy.read_pending.available_permits(), MAX_PENDING_READERS);
            assert_eq!(policy.read_work.available_permits(), 0);
            drop(permit);
            drop(second);
            assert_eq!(policy.read_work.available_permits(), 2);
            Ok(())
        }

        #[tokio::test]
        async fn internal_read_timeout_returns_original_busy_without_starting_work()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let _first = policy.read_permit(ReadAdmission::Immediate).await?;
            let _second = policy.read_permit(ReadAdmission::Immediate).await?;
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let failure = timeout(
                WAIT,
                policy.read_with_admission_staged(ReadAdmission::Internal, move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(())
                }),
            )
            .await
            .map_err(io::Error::other)?
            .expect_err("the internal admission deadline must expire");
            assert_eq!(failure.stage, ReadStage::Admission);
            assert_eq!(failure.error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(failure.error.to_string(), "policy coordinator is busy");
            assert_eq!(policy.read_pending.available_permits(), MAX_PENDING_READERS);
            assert_eq!(policy.read_work.available_permits(), 0);
            assert!(!called.load(Ordering::Acquire));
            Ok(())
        }

        #[tokio::test]
        async fn cancelling_a_queued_internal_read_does_not_spawn_its_operation() -> io::Result<()>
        {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let first = policy.read_permit(ReadAdmission::Immediate).await?;
            let second = policy.read_permit(ReadAdmission::Immediate).await?;
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let mut read = Box::pin(policy.read_with_admission(
                ReadAdmission::Internal,
                move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(())
                },
            ));
            assert!(futures_util::poll!(&mut read).is_pending());
            assert_eq!(
                policy.read_pending.available_permits(),
                MAX_PENDING_READERS - 1
            );
            drop(read);
            assert_eq!(policy.read_pending.available_permits(), MAX_PENDING_READERS);
            drop(first);
            drop(second);
            policy.read(|_| Ok(())).await?;
            assert_eq!(policy.read_work.available_permits(), 2);
            assert!(!called.load(Ordering::Acquire));
            Ok(())
        }

        /// A cancelled async waiter cannot join its blocking worker. Release and wait
        /// for that worker before fixture teardown, including after an assertion fails.
        struct CancelledInternalRead {
            held: Vec<OwnedSemaphorePermit>,
            release: Option<mpsc::Sender<()>>,
            completed: Option<mpsc::Receiver<()>>,
            policy: Arc<Coordinator>,
        }

        impl CancelledInternalRead {
            fn finish(&mut self) -> io::Result<()> {
                self.held.clear();
                self.release.take();
                if let Some(completed) = self.completed.take() {
                    completed.recv_timeout(WAIT).map_err(io::Error::other)?;
                    let deadline = Instant::now() + WAIT;
                    while self.policy.read_work.available_permits() != 2 {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "cancelled internal read retained its slot",
                            ));
                        }
                        thread::yield_now();
                    }
                }
                Ok(())
            }
        }

        impl Drop for CancelledInternalRead {
            fn drop(&mut self) {
                let _ = self.finish();
            }
        }

        #[tokio::test]
        async fn cancelling_an_admitted_internal_read_keeps_its_worker_slot() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let first = policy.read_permit(ReadAdmission::Immediate).await?;
            let second = policy.read_permit(ReadAdmission::Immediate).await?;
            let (started, waiting) = oneshot::channel();
            let (release, blocked) = mpsc::channel();
            let (finished, completed) = mpsc::channel();
            let mut cleanup = CancelledInternalRead {
                held: vec![first, second],
                release: Some(release),
                completed: Some(completed),
                policy: policy.clone(),
            };
            let mut read = Box::pin(policy.read_with_admission(
                ReadAdmission::Internal,
                move |_| {
                    let _ = started.send(());
                    let _ = blocked.recv_timeout(WAIT);
                    let _ = finished.send(());
                    Ok(())
                },
            ));
            assert!(futures_util::poll!(&mut read).is_pending());
            assert_eq!(
                policy.read_pending.available_permits(),
                MAX_PENDING_READERS - 1
            );
            drop(cleanup.held.pop());
            assert!(futures_util::poll!(&mut read).is_pending());
            timeout(WAIT, waiting)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            assert_eq!(policy.read_pending.available_permits(), MAX_PENDING_READERS);
            drop(read);
            assert_eq!(policy.read_work.available_permits(), 0);
            let failure = policy.read_staged(|_| Ok(())).await.unwrap_err();
            assert_eq!(failure.stage, ReadStage::Admission);
            cleanup.held.clear();
            policy.read(|_| Ok(())).await?;
            assert_eq!(policy.read_work.available_permits(), 1);
            cleanup.finish()?;
            assert_eq!(policy.read_work.available_permits(), 2);

            Ok(())
        }
    }
    mod read_diagnostics {
        use std::{
            sync::{
                atomic::{AtomicBool, Ordering},
                mpsc,
            },
            thread,
            time::Instant,
        };

        use tokio::{sync::oneshot, time::timeout};

        use super::*;

        const WAIT: Duration = Duration::from_secs(10);

        /// Keep the real read worker joinable. Drop releases it even if a later
        /// assertion fails, so the runtime and fixture do not outlive blocked work.
        struct HeldRead {
            release: Option<mpsc::Sender<()>>,
            thread: Option<thread::JoinHandle<io::Result<()>>>,
        }

        impl HeldRead {
            async fn new(policy: Arc<Coordinator>) -> io::Result<Self> {
                let runtime = tokio::runtime::Handle::current();
                let (started, waiting) = oneshot::channel();
                let (release, blocked) = mpsc::channel();
                let thread = thread::Builder::new()
                    .name("policy-test-read-holder".into())
                    .spawn(move || {
                        runtime.block_on(policy.read(move |_| {
                            let _ = started.send(());
                            let _ = blocked.recv_timeout(WAIT);
                            Ok(())
                        }))
                    })?;
                let holder = Self {
                    release: Some(release),
                    thread: Some(thread),
                };
                timeout(WAIT, waiting)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)?;
                Ok(holder)
            }

            fn finish(mut self) -> io::Result<()> {
                self.release.take();
                self.thread
                    .take()
                    .expect("held read worker")
                    .join()
                    .map_err(|_| io::Error::other("held read worker panicked"))?
            }
        }

        impl Drop for HeldRead {
            fn drop(&mut self) {
                self.release.take();
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }

        #[tokio::test]
        async fn occupied_read_workers_fail_at_admission_without_calling_the_operation()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let first = HeldRead::new(policy.clone()).await?;
            let second = HeldRead::new(policy.clone()).await?;
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let failure = policy
                .read_staged(move |_| {
                    observed.store(true, Ordering::Release);
                    Ok(())
                })
                .await
                .expect_err("two occupied read slots must reject without queueing");
            assert_eq!(failure.stage, ReadStage::Admission);
            assert_eq!(failure.error.kind(), io::ErrorKind::WouldBlock);
            assert!(!called.load(Ordering::Acquire));
            assert_eq!(policy.read_work.available_permits(), 0);
            second.finish()?;
            first.finish()?;
            assert_eq!(policy.read_work.available_permits(), 2);
            assert_eq!(
                policy
                    .read_staged(|_| Ok(7))
                    .await
                    .map_err(|error| error.error)?,
                7
            );
            Ok(())
        }

        #[tokio::test]
        async fn an_operation_busy_error_is_not_read_admission() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let failure = policy
                .read_staged(|_| Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock)))
                .await
                .expect_err("operation must retain its own busy error");
            assert_eq!(failure.stage, ReadStage::Operation);
            assert_eq!(failure.error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(policy.read_work.available_permits(), 2);
            Ok(())
        }

        #[tokio::test]
        async fn read_diagnostics_leave_the_original_immediate_typed_source_intact()
        -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let failure = policy
                .read_staged(|_| Err::<(), _>(io::Error::other(Error::PublicationFailed)))
                .await
                .expect_err("operation must fail");
            assert_eq!(failure.stage, ReadStage::Operation);
            let legacy = policy
                .read(|_| Err::<(), _>(io::Error::other(Error::PublicationFailed)))
                .await
                .expect_err("legacy read must retain the original error");
            for error in [failure.error, legacy] {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert!(matches!(
                    error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<Error>()),
                    Some(Error::PublicationFailed)
                ));
            }
            Ok(())
        }

        /// Dropping the awaiting read intentionally loses its JoinHandle, just as a
        /// transport cancellation does. Release and wait for its blocking operation
        /// before fixture teardown, including on assertion failure.
        struct CancelledRead {
            release: Option<mpsc::Sender<()>>,
            completed: Option<mpsc::Receiver<()>>,
            policy: Arc<Coordinator>,
        }

        impl CancelledRead {
            fn finish(&mut self) -> io::Result<()> {
                self.release.take();
                if let Some(completed) = self.completed.take() {
                    completed.recv_timeout(WAIT).map_err(io::Error::other)?;
                    // The operation reports completion just before the enclosing
                    // worker drops its permit. No async executor work is needed here.
                    let deadline = Instant::now() + WAIT;
                    while self.policy.read_work.available_permits() != 2 {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "cancelled read worker retained its slot",
                            ));
                        }
                        thread::yield_now();
                    }
                }
                Ok(())
            }
        }

        impl Drop for CancelledRead {
            fn drop(&mut self) {
                let _ = self.finish();
            }
        }

        #[tokio::test]
        async fn cancelling_the_waiter_keeps_the_started_worker_read_slot() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let (started, waiting) = oneshot::channel();
            let (release, blocked) = mpsc::channel();
            let (finished, completed) = mpsc::channel();
            let mut cleanup = CancelledRead {
                release: Some(release),
                completed: Some(completed),
                policy: policy.clone(),
            };
            let mut read = Box::pin(policy.read_staged(move |_| {
                let _ = started.send(());
                let _ = blocked.recv_timeout(WAIT);
                let _ = finished.send(());
                Ok(())
            }));
            assert!(futures_util::poll!(&mut read).is_pending());
            timeout(WAIT, waiting)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            drop(read);
            assert_eq!(policy.read_work.available_permits(), 1);
            policy.read(|_| Ok(())).await?;
            assert_eq!(policy.read_work.available_permits(), 1);
            cleanup.finish()?;
            assert_eq!(policy.read_work.available_permits(), 2);
            Ok(())
        }

        #[tokio::test]
        async fn a_panicking_read_worker_is_not_an_operation_failure() -> io::Result<()> {
            let fixture = Fixture::new()?;
            let policy = fixture.coordinator()?;
            let failure = policy
                .read_staged(|_| -> io::Result<()> { panic!("read diagnostic worker test") })
                .await
                .expect_err("worker panic must be classified");
            assert_eq!(failure.stage, ReadStage::Worker);
            assert_eq!(failure.error.kind(), io::ErrorKind::Other);
            assert!(matches!(
                failure
                    .error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<Error>()),
                Some(Error::WorkerUnavailable)
            ));
            assert_eq!(policy.read_work.available_permits(), 2);
            Ok(())
        }
    }

    #[tokio::test]
    async fn cancelled_metadata_response_keeps_the_actual_writer_and_update_gate() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let coordinator = fixture.coordinator()?;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (finished, completed) = tokio::sync::oneshot::channel();
        let mut metadata = Box::pin(coordinator.metadata_write(move |directory| {
            let gate = store::update_lock(directory)?;
            let _ = entered.send(());
            // Bound even a failed assertion's blocking worker independently of the
            // async runtime. Sender drop also wakes it without keeping the test alive.
            let _ = released.recv_timeout(Duration::from_secs(2));
            drop(gate);
            let _ = finished.send(());
            Ok(())
        }));
        assert!(futures_util::poll!(&mut metadata).is_pending());
        started.await.map_err(io::Error::other)?;
        drop(metadata);
        assert_eq!(coordinator.write_work.available_permits(), 0);
        assert!(matches!(
            store::update_lock(&fixture.directory),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        // A policy edit queues behind the detached worker rather than acquiring the
        // same update gate concurrently and returning a false fast-busy result.
        let mut change = Box::pin(coordinator.change(
            fixture.administrator.clone(),
            1,
            PolicyChange::CreateUser {
                name: "after cancelled metadata response".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 1,
            },
        ));
        assert!(futures_util::poll!(&mut change).is_pending());
        drop(release);
        completed.await.map_err(io::Error::other)?;
        assert_eq!(change.await?.revision, 2);
        assert_eq!(coordinator.reader().revision()?, 2);
        Ok(())
    }

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$Zml4dHVyZQ";

    struct Fixture {
        directory: PathBuf,
        administrator: String,
    }

    impl Fixture {
        fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("cannot create policy admission fixture identity"))?;
            let directory = std::env::temp_dir().join(format!(
                "vproxy-policy-admission-{}",
                URL_SAFE_NO_PAD.encode(random)
            ));
            store::initialize(&directory, "admission test", "admin", PHC)?;
            let connection = rusqlite::Connection::open_with_flags(
                directory.join("management.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(io::Error::other)?;
            let administrator = connection
                .query_row("SELECT id FROM administrators", [], |row| row.get(0))
                .map_err(io::Error::other)?;
            Ok(Self {
                directory,
                administrator,
            })
        }

        fn coordinator(&self) -> io::Result<Arc<Coordinator>> {
            Coordinator::new(
                self.directory.clone(),
                store::load_policy(&self.directory)?,
                Arc::new(store::lock(&self.directory)?),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn writer_waiters_are_bounded_cancel_safe_and_fifo() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let coordinator = fixture.coordinator()?;
        let active = coordinator.writer().await?;
        let mut waiters = (0..MAX_PENDING_WRITERS)
            .map(|_| Box::pin(coordinator.writer()))
            .collect::<Vec<_>>();
        for waiter in &mut waiters {
            assert!(futures_util::poll!(waiter).is_pending());
        }
        assert_eq!(coordinator.write_pending.available_permits(), 0);
        let mut overflow = Box::pin(coordinator.writer());
        let Poll::Ready(Err(error)) = futures_util::poll!(&mut overflow) else {
            panic!("a full writer queue must reject without waiting");
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        // Cancellation really drops the owned future, freeing both its pending
        // budget and its place in the existing writer semaphore's FIFO queue.
        drop(waiters.remove(0));
        assert_eq!(coordinator.write_pending.available_permits(), 1);
        let mut replacement = Box::pin(coordinator.writer());
        assert!(futures_util::poll!(&mut replacement).is_pending());
        assert_eq!(coordinator.write_pending.available_permits(), 0);
        drop(active);

        for waiter in &mut waiters {
            assert!(futures_util::poll!(&mut replacement).is_pending());
            let Poll::Ready(permit) = futures_util::poll!(waiter) else {
                panic!("the next admitted waiter must hold the sole writer permit");
            };
            let permit = permit?;
            assert_eq!(coordinator.write_work.available_permits(), 0);
            drop(permit);
        }
        let permit = replacement.await?;
        assert_eq!(
            coordinator.write_pending.available_permits(),
            MAX_PENDING_WRITERS
        );
        assert_eq!(coordinator.write_work.available_permits(), 0);
        drop(permit);
        assert_eq!(coordinator.write_work.available_permits(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn writer_wait_timeout_keeps_the_original_busy_error_and_releases_its_budget()
    -> io::Result<()> {
        let fixture = Fixture::new()?;
        let coordinator = fixture.coordinator()?;
        let _active = coordinator.writer().await?;
        let error = coordinator.writer().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(error.to_string(), "policy coordinator is busy");
        assert_eq!(
            coordinator.write_pending.available_permits(),
            MAX_PENDING_WRITERS
        );
        assert_eq!(coordinator.write_work.available_permits(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn traffic_write_diagnostics_preserve_the_original_typed_error() -> io::Result<()> {
        let fixture = Fixture::new()?;
        let coordinator = fixture.coordinator()?;
        let failure = coordinator
            .traffic_write_staged(|_| Err::<(), _>(io::Error::other(Error::PublicationFailed)))
            .await
            .expect_err("store operation must fail");
        assert!(matches!(failure.stage, TrafficWriteStage::Store));
        assert_eq!(failure.error.kind(), io::ErrorKind::Other);
        assert!(matches!(
            failure
                .error
                .get_ref()
                .and_then(|source| source.downcast_ref::<Error>()),
            Some(Error::PublicationFailed)
        ));

        // The old entry point must return the error itself, not an io::Error whose
        // outer source is the diagnostic wrapper. Existing wire mapping downcasts
        // that immediate source rather than searching an arbitrary chain.
        let error = coordinator
            .traffic_write(|_| Err::<(), _>(io::Error::other(Error::PublicationFailed)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<Error>()),
            Some(Error::PublicationFailed)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn queued_status_observes_the_committed_and_published_writer_revision() -> io::Result<()>
    {
        let fixture = Fixture::new()?;
        let coordinator = fixture.coordinator()?;
        coordinator.activate().await?;
        let connection = rusqlite::Connection::open(fixture.directory.join("management.sqlite3"))
            .map_err(io::Error::other)?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(io::Error::other)?;
        let mut change = Box::pin(coordinator.change(
            fixture.administrator.clone(),
            1,
            PolicyChange::CreateUser {
                name: "queued writer".into(),
                protocols: vec![crate::access::Protocol::Http],
                concurrent_limit: 1,
            },
        ));
        // The first poll moves admission into the real blocking mutation worker.
        // Our SQL lock prevents commit while the observation joins its writer queue.
        assert!(futures_util::poll!(&mut change).is_pending());
        let mut status = Box::pin(coordinator.status());
        assert!(futures_util::poll!(&mut status).is_pending());
        assert_eq!(
            coordinator.write_pending.available_permits(),
            MAX_PENDING_WRITERS - 1
        );
        assert_eq!(coordinator.reader().revision()?, 1);
        connection
            .execute_batch("ROLLBACK")
            .map_err(io::Error::other)?;

        assert_eq!(change.await?.revision, 2);
        let status = status.await?;
        assert!(status.running);
        assert_eq!(status.saved_revision, 2);
        assert_eq!(status.applied_revision, Some(2));
        assert_eq!(status.durable_applied_revision, Some(2));
        assert_eq!(status.user_count, 1);
        Ok(())
    }
}
