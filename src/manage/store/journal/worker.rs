//! One source thread behind the existing Coordinator writer admission. It owns
//! SQL/author/update/Offline and the original Reader owner, leaving Tokio's
//! blocking capacity available to both ends of witness authorization.

use super::{owner::Owner, *};
use crate::manage::{
    node::control::{Offline, witness::Operation},
    store::{traffic, users},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Mutex, mpsc},
    thread::{self, JoinHandle},
};
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};

type Request<'a> = dyn FnMut(Operation) -> io::Result<Fetched<Record>> + 'a;
type Job = Box<dyn FnOnce(&mut Owner<'_>, &mut Connection, &mut Request<'_>) + Send>;

/// Startup material comes only from the confirmed original SQL view. The worker
/// is not a backup/config freshness permit and cannot create a source baseline.
pub(in crate::manage) struct Ready {
    pub(in crate::manage) reader: crate::access::Reader,
    pub(in crate::manage) restoration: traffic::Status,
}

/// The one-slot mailbox is a handoff, not another admission queue. Every job
/// owns the Coordinator's single writer permit through publication and receipt;
/// ordinary eight-waiter/250ms admission remains with that Coordinator.
pub(in crate::manage) struct Worker {
    /// Immutable capture pins, not a substitute for a fresh read on the owner.
    configuration: Option<source::Configuration>,
    key_sha256: [u8; 32],
    sender: Mutex<Option<mpsc::SyncSender<Job>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// None is live; Some(failed) is sent after all source guards/SQL drop.
    /// Watch retains terminal state for cancellation-safe repeated shutdown.
    done: watch::Receiver<Option<bool>>,
}

impl Worker {
    /// Unbound fixtures exercise the same thread/ownership kernel. There is no
    /// production entry that omits the registered configuration comparison.
    #[cfg(test)]
    pub(in crate::manage) async fn start(
        directory: PathBuf,
        author: Arc<Guard>,
        enrollment: Enrollment,
        endpoint: String,
        identity: tls::NodeIdentity,
    ) -> io::Result<(Self, Ready)> {
        Self::start_inner(directory, author, enrollment, endpoint, identity, None).await
    }

    /// Open an already-staged source on its dedicated thread. Inspect must be
    /// confirmed before returning the actual Reader. Cancellation drops the
    /// sole sender: startup can finish but cannot leave an idle orphan worker.
    /// No migration, baseline initialization or uncertainty reconciliation runs.
    /// The witness endpoint/enrollment and identity all come from that capture;
    /// no independent startup arguments or source-file reload are accepted.
    /// Exact configuration revision/digest must match under the retained gates.
    pub(in crate::manage) async fn start_registered(
        directory: PathBuf,
        author: Arc<Guard>,
        registered: crate::manage::snapshot::Registered,
    ) -> io::Result<(Self, Ready, crate::manage::snapshot::inputs::Prepared)> {
        let input_directory = directory.clone();
        let input_author = author.clone();
        let (reference, inputs) = tokio::task::spawn_blocking(move || {
            input_author.ensure(&input_directory)?;
            registered.into_inputs(&input_directory)
        })
        .await
        .map_err(|_| unavailable())??;
        let binding = inputs.configuration.source.as_ref().ok_or_else(denied)?;
        let (worker, ready) = Self::start_inner(
            directory,
            author,
            binding.enrollment.clone(),
            binding.endpoint.clone(),
            inputs.node.clone(),
            Some(reference),
        )
        .await?;
        Ok((worker, ready, inputs))
    }

    async fn start_inner(
        directory: PathBuf,
        author: Arc<Guard>,
        enrollment: Enrollment,
        endpoint: String,
        identity: tls::NodeIdentity,
        configuration: Option<source::Configuration>,
    ) -> io::Result<(Self, Ready)> {
        let key_sha256 = identity.key_sha256()?;
        let handle = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let (ready, waiting) = oneshot::channel();
        let (done, completion) = watch::channel(None);
        let thread = thread::Builder::new()
            .name("vproxy-source".into())
            .spawn(move || {
                let mut ready = Some(ready);
                let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                    // Move both into this unwind boundary. Its terminal signal
                    // must follow queued-job/permit and author release too.
                    let author = author;
                    let receiver = receiver;
                    author.ensure(&directory)?;
                    let gate = super::super::update_lock(&directory)?;
                    let offline = Offline::new(
                        &directory,
                        author.clone(),
                        &enrollment.peer_node_id,
                        identity,
                    )?;
                    let scope = Scope {
                        directory: &directory,
                        author: &author,
                        gate: &gate,
                        enrollment: &enrollment,
                    };
                    let mut connection = open(&scope)?;
                    let mut request = |op| {
                        handle.block_on(offline.request(&endpoint, &enrollment.witness_node_id, op))
                    };
                    let mut owner = Owner::open_configuration(
                        scope,
                        &mut connection,
                        &mut request,
                        configuration,
                    )?;
                    let state = Ready {
                        reader: owner.reader(),
                        restoration: owner.restoration().clone(),
                    };
                    if ready
                        .take()
                        .ok_or_else(unavailable)?
                        .send(Ok(state))
                        .is_err()
                    {
                        return Ok(());
                    }
                    while let Ok(job) = receiver.recv() {
                        job(&mut owner, &mut connection, &mut request);
                    }
                    Ok(())
                }));
                let failed = match result {
                    Ok(Ok(())) => false,
                    Ok(Err(error)) => {
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Err(error));
                        }
                        true
                    }
                    Err(_) => {
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(Err(unavailable()));
                        }
                        true
                    }
                };
                // The inner closure has returned/unwound: no source guard, original
                // policy, connection or Offline capability survives this signal.
                done.send_replace(Some(failed));
            })?;
        let worker = Self {
            configuration,
            key_sha256,
            sender: Mutex::new(Some(sender)),
            thread: Mutex::new(Some(thread)),
            done: completion,
        };
        let ready = waiting.await.map_err(|_| unavailable())??;
        Ok((worker, ready))
    }

    /// Match a node transport's capture before admitting its startup read.
    /// Confirmation and current SQL state are checked by the subsequent turn.
    pub(in crate::manage) fn configured_for(
        &self,
        reference: source::Configuration,
        key_sha256: [u8; 32],
    ) -> bool {
        self.configuration == Some(reference) && self.key_sha256 == key_sha256
    }

    fn enqueue(&self, job: Job) -> io::Result<()> {
        // The short lock linearizes enqueue with close; it never spans SQL,
        // TLS, a blocking send or an await. No Sender clone escapes this lock.
        let sender = self.sender.lock().map_err(|_| unavailable())?;
        sender
            .as_ref()
            .ok_or_else(unavailable)?
            .try_send(job)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "source handoff is busy")
                }
                mpsc::TrySendError::Disconnected(_) => unavailable(),
            })
    }

    /// Submit trusted bounded DML under an already-acquired writer permit.
    /// Dropping the response future cannot cancel accepted work or release its
    /// permit. A policy publication's applied receipt is another witnessed
    /// metadata transaction; a lost receipt prevents one-time result delivery.
    /// Terminal read observations do not publish or acknowledge another policy.
    pub(in crate::manage) async fn write<T: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T> + Send + 'static,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<(T, bool)> {
        self.write_guarded(permit, (), change, running).await
    }

    /// Retain an external delivery claim/capacity guard outside the SQL
    /// callback through witness confirmation and result publication. Callback
    /// locals alone would drop before Reserve/COMMIT/Confirm. Cancellation or
    /// unwind releases the guard only in the actual owning worker.
    pub(in crate::manage) async fn write_guarded<G: Send + 'static, T: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        guard: G,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T> + Send + 'static,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<(T, bool)> {
        self.write_then(permit, guard, change, |value| Ok(value), running)
            .await
    }

    /// Run an owned synchronous continuation only after exact confirmation and
    /// any policy acknowledgement. It retains writer/external guards through
    /// RAM publication even if the waiting future is cancelled. No SQL borrow
    /// escapes into the continuation and no RAM mutex spans witness I/O.
    pub(in crate::manage) async fn write_then<
        G: Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
    >(
        &self,
        permit: OwnedSemaphorePermit,
        guard: G,
        change: impl FnOnce(&mut Transaction<'_>) -> io::Result<T> + Send + 'static,
        finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<(R, bool)> {
        self.write_mode_then(permit, guard, false, |tx, _| change(tx), finish, running)
            .await
    }

    /// Capture bounded history chunks on the accepted writer, not separate
    /// jobs/transactions. Cancellation retains the permit through confirmation
    /// and the owned synchronous publication, just like ordinary writes.
    pub(in crate::manage) async fn history_then<T: Send + 'static, R: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        change: impl FnOnce(&mut Transaction<'_>, &mut dyn Checkpoints) -> io::Result<T>
        + Send
        + 'static,
        finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<(R, bool)> {
        self.write_mode_then(
            permit,
            (),
            true,
            |tx, checkpoints| change(tx, checkpoints.ok_or_else(invalid)?),
            finish,
            running,
        )
        .await
    }

    async fn write_mode_then<G: Send + 'static, T: Send + 'static, R: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        guard: G,
        history: bool,
        change: impl FnOnce(&mut Transaction<'_>, Option<&mut dyn Checkpoints>) -> io::Result<T>
        + Send
        + 'static,
        finish: impl FnOnce(T) -> io::Result<R> + Send + 'static,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<(R, bool)> {
        let (sent, response) = oneshot::channel();
        self.enqueue(Box::new(move |owner, connection, request| {
            let _permit = permit;
            let _guard = guard;
            let result = (|| {
                let before = owner
                    .reader()
                    .revision()
                    .map_err(super::driver::uncertain)?;
                let value = owner.run_mode(connection, &mut |op| request(op), history, change)?;
                let running = running();
                let after = owner
                    .reader()
                    .revision()
                    .map_err(super::driver::uncertain)?;
                if after != before {
                    acknowledge(owner, connection, request, running)
                        .map_err(super::driver::uncertain)?;
                }
                // Publication failure cannot undo the confirmed SQL. The
                // consumer retains its original batch and may confirm that
                // receipt again; do not rerun business SQL or infer rollback.
                Ok((finish(value)?, running))
            })();
            let _ = sent.send(result);
        }))?;
        // Once enqueued, worker loss is outcome-unknown, never a definite busy
        // or permission rejection. Any retained intent remains on disk.
        response
            .await
            .map_err(|_| super::driver::uncertain(unavailable()))?
    }

    /// Resolve only the retained original operation; never return a secret or
    /// rerun its business callback. A matching applied receipt is idempotent.
    pub(in crate::manage) async fn reconcile(
        &self,
        permit: OwnedSemaphorePermit,
        running: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<()> {
        let (sent, response) = oneshot::channel();
        self.enqueue(Box::new(move |owner, connection, request| {
            let _permit = permit;
            let result = owner
                .reconcile(connection, &mut |op| request(op))
                .and_then(|()| {
                    acknowledge(owner, connection, request, running())
                        .map_err(super::driver::uncertain)
                });
            let _ = sent.send(result);
        }))?;
        response
            .await
            .map_err(|_| super::driver::uncertain(unavailable()))?
    }

    /// Called only after real listener readiness. An unavailable original
    /// Reader refuses before reconciliation; activation cannot silently resolve
    /// an earlier unknown mutation. Repeated healthy activation is idempotent.
    pub(in crate::manage) async fn activate(
        &self,
        permit: OwnedSemaphorePermit,
        ready: impl FnOnce() + Send + 'static,
    ) -> io::Result<()> {
        let (sent, response) = oneshot::channel();
        self.enqueue(Box::new(move |owner, connection, request| {
            let _permit = permit;
            let result = (|| {
                owner
                    .reader()
                    .revision()
                    .map_err(super::driver::uncertain)?;
                owner.reconcile(connection, &mut |op| request(op))?;
                acknowledge(owner, connection, request, true).map_err(super::driver::uncertain)?;
                ready();
                Ok(())
            })();
            let _ = sent.send(result);
        }))?;
        response
            .await
            .map_err(|_| super::driver::uncertain(unavailable()))?
    }

    /// Stop accepting jobs synchronously, then drain the accepted handoff and
    /// join only after terminal guard release. This wait may be cancelled and
    /// resumed. The caller must keep Tokio alive for outstanding witness TLS.
    /// No timeout here converts a committed/unknown write into cancellation.
    pub(in crate::manage) async fn shutdown(&self) -> io::Result<()> {
        self.sender.lock().map_err(|_| unavailable())?.take();
        let mut done = self.done.clone();
        let failed = done
            .wait_for(|state| state.is_some())
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let thread = self.thread.lock().map_err(|_| unavailable())?.take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join().map_err(|_| unavailable()))
                .await
                .map_err(|_| unavailable())??;
        }
        if failed { Err(unavailable()) } else { Ok(()) }
    }
}

fn acknowledge(
    owner: &mut Owner<'_>,
    connection: &mut Connection,
    request: &mut Request<'_>,
    running: bool,
) -> io::Result<()> {
    if !running {
        return Ok(());
    }
    let revision = owner
        .reader()
        .revision()
        .map_err(super::driver::uncertain)?;
    if users::read_state(connection)?.1 == Some(revision) {
        return Ok(());
    }
    owner.run(connection, &mut |op| request(op), |tx| {
        users::record_applied_in(tx, revision)
    })
}

fn unavailable() -> io::Error {
    io::Error::other("source worker is unavailable")
}
