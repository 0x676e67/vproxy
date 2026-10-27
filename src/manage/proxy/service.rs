//! Cold listener-group control for the Web service settings. This owns no
//! credentials or durable configuration: the management coordinator must
//! authorize and persist an operation before submitting it here.
//!
//! A single native owner keeps forwarding runtimes outside async destruction.
//! Its timer-only Tokio driver waits for commands/readiness, never forwards
//! traffic. Reconfiguration uses the existing bind, authentication and drain
//! implementation; no per-connection lock or storage access is added.

use std::{io, sync::Arc, sync::mpsc as sync_mpsc, time::Duration};

use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::{Certificates, Lifecycle, ListenerView, Prepared, Running, ShutdownResult};
use crate::{access::Reader, manage::store};

mod managed;
pub(in crate::manage) use managed::Managed;

const START_TIMEOUT: Duration = Duration::from_secs(15);
const OWNER_TIMEOUT: Duration = Duration::from_secs(24);

/// Current process-local state, not a saved configuration or an end-to-end
/// connectivity claim. Stopping continues to use the protocol-specific drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Phase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

/// One coherent cold observation. A historical planned-drain lifecycle may
/// remain after its workers stop; only `phase == Running` means live listeners.
/// Errors expose their class, not filesystem paths or TLS private material.
#[derive(Clone)]
pub(in crate::manage) struct View {
    /// Namespace belongs to this Control, not a database revision. The API must
    /// use its durable operation/configuration identity across process restarts.
    pub(in crate::manage) generation: u64,
    /// Last configuration actually reached by this owner, distinct from the
    /// desired SQL revision and access-policy publication revision.
    pub(in crate::manage) configuration_revision: Option<u64>,
    pub(in crate::manage) phase: Phase,
    pub(in crate::manage) endpoints: Vec<ListenerView>,
    pub(in crate::manage) certificates: Certificates,
    pub(in crate::manage) runtime: Option<Lifecycle>,
    /// All previously retired worker pools are confirmed stopped. This is a
    /// replacement gate, not a claim that the current running pool has stopped.
    pub(in crate::manage) cleanup_confirmed: bool,
    pub(in crate::manage) failure: Option<io::ErrorKind>,
    #[cfg(test)]
    pub(in crate::manage) addresses: Vec<std::net::SocketAddr>,
}

impl Default for View {
    fn default() -> Self {
        Self {
            generation: 0,
            configuration_revision: None,
            phase: Phase::Stopped,
            endpoints: Vec::new(),
            certificates: Certificates::default(),
            runtime: None,
            cleanup_confirmed: true,
            failure: None,
            #[cfg(test)]
            addresses: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(in crate::manage) enum Error {
    #[error("proxy service generation changed")]
    GenerationConflict,
    #[error("proxy service operation queue is full")]
    Busy,
    #[error("proxy service is stopping")]
    Stopping,
    #[error("proxy service owner is unavailable")]
    Unavailable,
    #[error("previous proxy worker cleanup is unconfirmed")]
    CleanupUnconfirmed,
}

impl Error {
    fn io(self) -> io::Error {
        let kind = match self {
            Self::GenerationConflict => io::ErrorKind::AlreadyExists,
            Self::Busy => io::ErrorKind::WouldBlock,
            Self::Stopping | Self::Unavailable => io::ErrorKind::BrokenPipe,
            Self::CleanupUnconfirmed => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

enum Operation {
    #[cfg(test)]
    Replace {
        expected_generation: u64,
        // Test-only prepared profiles include the Linux eBPF configuration.
        // Keep that large fixture off the event enum's stack representation;
        // production commands do not allocate this box.
        prepared: Option<Box<Prepared>>,
    },
    Configure {
        administrator: String,
        request: store::proxy_service::Request,
    },
    Restore,
}

struct Command {
    operation: Operation,
    reply: oneshot::Sender<io::Result<View>>,
}

/// Cloneable request surface only. The process owner, not these clones or an
/// HTTP waiter, determines when workers shut down and releases the author lease.
#[derive(Clone)]
pub(in crate::manage) struct Control {
    commands: mpsc::Sender<Command>,
    state: watch::Receiver<View>,
    stopping: CancellationToken,
}

impl Control {
    /// A closed worker is unavailable, never a stale successful running state.
    pub(in crate::manage) fn snapshot(&self) -> io::Result<View> {
        self.state
            .has_changed()
            .map_err(|_| Error::Unavailable.io())?;
        Ok(self.state.borrow().clone())
    }

    pub(in crate::manage) fn subscribe(&self) -> watch::Receiver<View> {
        self.state.clone()
    }

    pub(in crate::manage) fn shutdown(&self) {
        self.stopping.cancel();
    }

    /// Failure of the owner, unlike a recoverable listener failure reported in
    /// its View, is fatal to supervision. No polling timer or SQL work is used.
    pub(in crate::manage) async fn monitor(&self, shutdown: CancellationToken) -> io::Result<()> {
        let mut state = self.subscribe();
        loop {
            tokio::select! {
                biased;
                _=shutdown.cancelled()=>return Ok(()),
                changed=state.changed()=>changed.map_err(|_|Error::Unavailable.io())?,
            }
        }
    }

    /// Admit at most one queued operation in addition to the active one. Once
    /// queued, cancellation of its receipt does not cancel or repeat the work.
    /// A stale generation is checked again by the owner before touching sockets.
    #[cfg(test)]
    pub(in crate::manage) fn request(
        &self,
        expected_generation: u64,
        prepared: Option<Prepared>,
    ) -> io::Result<oneshot::Receiver<io::Result<View>>> {
        self.enqueue(Operation::Replace {
            expected_generation,
            prepared: prepared.map(Box::new),
        })
    }

    fn enqueue(&self, operation: Operation) -> io::Result<oneshot::Receiver<io::Result<View>>> {
        if self.stopping.is_cancelled() {
            return Err(Error::Stopping.io());
        }
        let (reply, receipt) = oneshot::channel();
        self.commands
            .try_send(Command { operation, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Busy.io(),
                mpsc::error::TrySendError::Closed(_) => Error::Unavailable.io(),
            })?;
        Ok(receipt)
    }

    /// Queue a non-secret intent. Socket and durable work belong to the native
    /// owner even if the HTTP wait disappears. Queue admission is not a saved
    /// receipt: callers recover by their exact original revision/request ID.
    pub(in crate::manage) async fn configure(
        &self,
        administrator: String,
        request: store::proxy_service::Request,
    ) -> io::Result<View> {
        self.enqueue(Operation::Configure {
            administrator,
            request,
        })?
        .await
        .map_err(|_| Error::Unavailable.io())?
    }

    pub(in crate::manage) async fn restore(&self) -> io::Result<View> {
        self.enqueue(Operation::Restore)?
            .await
            .map_err(|_| Error::Unavailable.io())?
    }

    /// Replace the current listener group, or stop it for `None`. A reply error
    /// after admission is not proof that the generation or saved state stayed
    /// unchanged; read the original operation through the management layer.
    #[cfg(test)]
    pub(in crate::manage) async fn apply(
        &self,
        expected_generation: u64,
        prepared: Option<Prepared>,
    ) -> io::Result<View> {
        self.request(expected_generation, prepared)?
            .await
            .map_err(|_| Error::Unavailable.io())?
    }
}

/// Native owner retained outside the management executor. `Drop` requests stop
/// without blocking an async worker; normal process cleanup must call `finish`
/// and use its `runtime_stopped` fact before finalizing traffic restoration.
pub(in crate::manage) struct Service {
    control: Control,
    ready: Option<oneshot::Receiver<io::Result<()>>>,
    completed: Option<sync_mpsc::Receiver<ShutdownResult>>,
}

impl Service {
    /// Create a bounded cold owner without binding proxy sockets. Keep this
    /// value outside Tokio and await `ready` before submitting configurations;
    /// thread/driver failures do not authorize another author or an open proxy.
    #[cfg(test)]
    pub(in crate::manage) fn spawn(access: Reader, author: Arc<store::Guard>) -> io::Result<Self> {
        Self::spawn_with(access, author, None)
    }

    pub(in crate::manage) fn managed(
        managed: Managed,
        author: Arc<store::Guard>,
    ) -> io::Result<Self> {
        Self::spawn_with(managed.policy.reader(), author, Some(managed))
    }

    fn spawn_with(
        access: Reader,
        author: Arc<store::Guard>,
        managed: Option<Managed>,
    ) -> io::Result<Self> {
        let (commands, receiver) = mpsc::channel(1);
        let (state, observation) = watch::channel(View::default());
        let stopping = CancellationToken::new();
        let (ready, readiness) = oneshot::channel();
        let (completed, completion) = sync_mpsc::sync_channel(1);
        let control = Control {
            commands,
            state: observation,
            stopping: stopping.clone(),
        };
        std::thread::Builder::new()
            .name("vproxy-proxy-service".into())
            .spawn(move || {
                // No owned forwarding runtime is captured by an async task. The
                // outer closure sends completion only after Worker drops its lease.
                let result = Worker::run(receiver, state, stopping, access, author, managed, ready);
                let _ = completed.send(result);
            })?;
        Ok(Self {
            control,
            ready: Some(readiness),
            completed: Some(completion),
        })
    }

    pub(in crate::manage) fn control(&self) -> Control {
        self.control.clone()
    }

    pub(in crate::manage) async fn ready(&mut self) -> io::Result<()> {
        let ready = self.ready.as_mut().ok_or_else(|| Error::Unavailable.io())?;
        let result = ready.await.map_err(|_| Error::Unavailable.io())?;
        self.ready = None;
        result
    }

    /// Outside async execution, cancel the actor and wait for its actual reaper.
    /// A timeout leaves ownership with that worker, never authorizes replacement.
    pub(in crate::manage) fn finish(mut self) -> ShutdownResult {
        self.control.stopping.cancel();
        let result = self
            .completed
            .take()
            .ok_or_else(|| Error::Unavailable.io())
            .and_then(|completion| {
                completion
                    .recv_timeout(OWNER_TIMEOUT)
                    .map_err(|error| match error {
                        sync_mpsc::RecvTimeoutError::Timeout => io::Error::new(
                            io::ErrorKind::TimedOut,
                            "proxy service cleanup timed out",
                        ),
                        sync_mpsc::RecvTimeoutError::Disconnected => Error::Unavailable.io(),
                    })
            });
        result.unwrap_or_else(|error| ShutdownResult {
            result: Err(error),
            runtime_stopped: false,
        })
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.control.stopping.cancel();
    }
}

struct Worker {
    state: watch::Sender<View>,
    stopping: CancellationToken,
    access: Reader,
    author: Arc<store::Guard>,
    running: Option<Running>,
    managed: Option<Managed>,
}

enum Event {
    Command(Option<Command>),
    Finished(io::Result<()>),
    Stop,
}

impl Worker {
    fn run(
        mut commands: mpsc::Receiver<Command>,
        state: watch::Sender<View>,
        stopping: CancellationToken,
        access: Reader,
        author: Arc<store::Guard>,
        managed: Option<Managed>,
        ready: oneshot::Sender<io::Result<()>>,
    ) -> ShutdownResult {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(2)
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let kind = error.kind();
                let _ = ready.send(Err(error));
                return ShutdownResult {
                    result: Err(io::Error::new(kind, "proxy service driver unavailable")),
                    runtime_stopped: true,
                };
            }
        };
        let mut worker = Self {
            state,
            stopping,
            access,
            author,
            running: None,
            managed,
        };
        if ready.send(Ok(())).is_err() {
            return ShutdownResult {
                result: Ok(()),
                runtime_stopped: true,
            };
        }
        loop {
            let event = runtime.block_on(async {
                if let Some(running) = worker.running.as_mut() {
                    tokio::select! {
                        biased;
                        _ = worker.stopping.cancelled() => Event::Stop,
                        result = running.finished() => Event::Finished(result),
                        command = commands.recv() => Event::Command(command),
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = worker.stopping.cancelled() => Event::Stop,
                        command = commands.recv() => Event::Command(command),
                    }
                }
            });
            match event {
                Event::Stop | Event::Command(None) => break,
                Event::Command(Some(command)) => {
                    let result = match command.operation {
                        #[cfg(test)]
                        Operation::Replace {
                            expected_generation,
                            prepared,
                        } => worker.apply(
                            &runtime,
                            expected_generation,
                            prepared.map(|value| *value),
                        ),
                        Operation::Configure {
                            administrator,
                            request,
                        } => worker.configure(&runtime, Some((administrator, request))),
                        Operation::Restore => worker.configure(&runtime, None),
                    };
                    let _ = command.reply.send(result);
                }
                Event::Finished(result) => {
                    if let Some(managed) = worker.managed.as_ref() {
                        managed.policy.deactivate();
                    }
                    let planned = worker
                        .running
                        .as_ref()
                        .map(|running| running.lifecycle().complete(&result))
                        .transpose()
                        .map(|value| value.unwrap_or(false));
                    let completion_failure = planned.as_ref().err().map(io::Error::kind);
                    let planned = planned.unwrap_or(false);
                    let failure = completion_failure
                        .or_else(|| result.err().map(|error| error.kind()))
                        .or_else(|| (!planned).then_some(io::ErrorKind::UnexpectedEof));
                    let cleanup = worker.reap(planned);
                    worker.state.send_modify(|view| {
                        // Cleanup uncertainty takes precedence over a driver
                        // error: replacement must not hide potentially live OS
                        // workers merely because completion already failed.
                        view.failure = cleanup.as_ref().err().map(io::Error::kind).or(failure);
                        view.phase = if planned && view.failure.is_none() && view.cleanup_confirmed
                        {
                            Phase::Stopped
                        } else {
                            Phase::Failed
                        };
                    });
                }
            }
        }
        if let Some(managed) = worker.managed.as_ref() {
            managed.policy.deactivate();
        }
        let result = worker.reap(false);
        let runtime_stopped = worker.state.borrow().cleanup_confirmed;
        let result = result.and_then(|()| {
            if runtime_stopped {
                Ok(())
            } else {
                Err(Error::CleanupUnconfirmed.io())
            }
        });
        worker.state.send_modify(|view| {
            view.phase = if result.is_ok() && runtime_stopped {
                Phase::Stopped
            } else {
                Phase::Failed
            };
            view.failure = result.as_ref().err().map(io::Error::kind);
        });
        // Drop the actor's timer runtime on this native thread, too.
        drop(runtime);
        ShutdownResult {
            result,
            runtime_stopped,
        }
    }

    fn reap(&mut self, retain_receipt: bool) -> io::Result<()> {
        let Some(running) = self.running.take() else {
            return Ok(());
        };
        self.state.send_modify(|view| view.phase = Phase::Stopping);
        let cleanup = running.finish();
        self.state.send_modify(|view| {
            view.cleanup_confirmed &= cleanup.runtime_stopped;
            if !retain_receipt {
                view.runtime = None;
                view.configuration_revision = None;
            }
            #[cfg(test)]
            {
                view.addresses.clear();
            }
        });
        cleanup.result.and_then(|()| {
            if cleanup.runtime_stopped {
                Ok(())
            } else {
                Err(Error::CleanupUnconfirmed.io())
            }
        })
    }

    fn apply(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        expected: u64,
        prepared: Option<Prepared>,
    ) -> io::Result<View> {
        if self.stopping.is_cancelled() {
            return Err(Error::Stopping.io());
        }
        let current = self.state.borrow().clone();
        if !current.cleanup_confirmed {
            return Err(Error::CleanupUnconfirmed.io());
        }
        if expected != current.generation {
            return Err(Error::GenerationConflict.io());
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("proxy service generation exhausted"))?;
        self.state.send_modify(|view| {
            view.generation = generation;
            view.failure = None;
            view.configuration_revision = None;
        });
        if let Err(error) = self.reap(false) {
            self.failed(error.kind());
            return Err(error);
        }
        // Stop may have arrived during the native bounded drain above. Do not
        // create another pool merely to cancel its readiness immediately.
        if self.stopping.is_cancelled() {
            self.failed(io::ErrorKind::BrokenPipe);
            return Err(Error::Stopping.io());
        }
        let Some(prepared) = prepared else {
            self.state.send_modify(|view| {
                view.phase = Phase::Stopped;
                view.runtime = None;
            });
            return Ok(self.state.borrow().clone());
        };
        self.state.send_modify(|view| {
            view.phase = Phase::Starting;
            view.endpoints = prepared.endpoints().to_vec();
            view.certificates = prepared.certificate_handle();
            view.runtime = None;
        });
        let started = super::start(prepared, self.access.clone(), self.author.clone());
        let result = match started {
            Ok(running) => {
                self.running = Some(running);
                runtime.block_on(async {
                    let running = self.running.as_mut().ok_or_else(|| Error::Unavailable.io())?;
                    tokio::select! {
                        biased;
                        _ = self.stopping.cancelled() => Err(Error::Stopping.io()),
                        ready = tokio::time::timeout(START_TIMEOUT, running.ready()) => ready
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy service startup timed out"))?,
                    }
                })
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let cleanup = self.reap(false);
            let error = cleanup.err().unwrap_or(error);
            self.failed(error.kind());
            return Err(error);
        }
        let running = self
            .running
            .as_ref()
            .ok_or_else(|| Error::Unavailable.io())?;
        self.state.send_modify(|view| {
            view.runtime = Some(running.lifecycle());
            view.phase = Phase::Running;
            #[cfg(test)]
            {
                view.addresses = running.addresses.clone();
            }
        });
        Ok(self.state.borrow().clone())
    }

    fn failed(&self, kind: io::ErrorKind) {
        self.state.send_modify(|view| {
            view.phase = Phase::Failed;
            view.failure = Some(kind);
        });
    }
}
