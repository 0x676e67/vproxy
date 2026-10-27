//! Shared graceful shutdown state for proxy servers and connection tasks.

use std::{future::Future, io, sync::Arc, time::Duration};

use tokio::{
    runtime::Handle as Worker,
    sync::watch,
    time::{Instant, timeout_at},
};

/// One runtime's shutdown direction never reverses. The first process-stop
/// request fixes its deadline; repeated requests cannot grant more drain time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shutdown {
    Active,
    #[cfg(any(feature = "management", test))]
    Draining,
    Stopping {
        deadline: Instant,
    },
}

/// Shared handle for graceful server shutdown.
///
/// The state is retained by `watch`, so tasks that start waiting after shutdown
/// was requested still return immediately.
#[derive(Clone)]
pub(crate) struct Handle {
    graceful_shutdown: watch::Sender<Shutdown>,
    /// Nonempty pool belonging to this server's actual runtime. Do not consult
    /// Pingora's global thread-local cache: recycled thread IDs can retain a
    /// previous runtime's pool after restart (Pingora 0.8.1).
    workers: Arc<[Worker]>,
}

impl Handle {
    /// A single-runtime fixture; production constructors must supply the actual
    /// forwarding pool through `Runtime::handle`, not the management executor.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_workers(vec![Worker::current()]).expect("one test runtime worker")
    }

    /// Bind shutdown and dispatch to one concrete nonempty worker pool.
    pub(super) fn with_workers(workers: Vec<Worker>) -> io::Result<Self> {
        if workers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy worker pool cannot be empty",
            ));
        }
        let (graceful_shutdown, _) = watch::channel(Shutdown::Active);
        Ok(Self {
            graceful_shutdown,
            workers: workers.into(),
        })
    }

    /// Select a worker in this runtime, preserving no-steal connection dispatch.
    /// This borrows an existing Tokio handle: no global lock, allocation, or
    /// payload-path operation is added. Cloning this shutdown handle adds one
    /// pool `Arc` increment at the existing connection/task ownership boundary.
    pub(crate) fn runtime_handle(&self) -> &Worker {
        let length = self.workers.len();
        let index = if length == 1 {
            0
        } else {
            crate::rand::random_u64() as usize % length
        };
        // with_workers establishes nonemptiness, and the immutable Arc slice's
        // length cannot change between selection and lookup.
        &self.workers[index]
    }

    /// Stop accepting on either maintenance quiesce or process shutdown.
    /// Late waiters observe the retained state, not a transient notification.
    pub(crate) async fn wait_graceful_shutdown(&self) {
        let mut graceful_shutdown = self.graceful_shutdown.subscribe();
        loop {
            let state = *graceful_shutdown.borrow_and_update();
            if state != Shutdown::Active || graceful_shutdown.changed().await.is_err() {
                return;
            }
        }
    }

    /// Wait only for the bounded process-stop phase. Maintenance alone must
    /// not terminate an already admitted operation or start its timeout.
    pub(crate) async fn wait_stopping(&self) {
        let mut changes = self.graceful_shutdown.subscribe();
        loop {
            let state = *changes.borrow_and_update();
            if matches!(state, Shutdown::Stopping { .. }) || changes.changed().await.is_err() {
                return;
            }
        }
    }

    /// Keep the same in-progress cleanup future across phase changes. A
    /// maintenance drain has no automatic deadline. Process stop adds only the
    /// supplied cleanup grace to its original absolute deadline, never to now.
    /// Cancellation drops this wait and its owned future; callers that retain
    /// task/permit ownership must still finish their normal outer cleanup.
    pub(crate) async fn wait_for_drain<F: Future>(
        &self,
        work: F,
        cleanup_grace: Duration,
    ) -> io::Result<F::Output> {
        let mut changes = self.graceful_shutdown.subscribe();
        tokio::pin!(work);
        loop {
            let state = *changes.borrow_and_update();
            if let Shutdown::Stopping { deadline } = state {
                let deadline = deadline.checked_add(cleanup_grace).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "proxy shutdown grace exceeds deadline range",
                    )
                })?;
                return timeout_at(deadline, work.as_mut()).await.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "proxy shutdown drain deadline elapsed",
                    )
                });
            }
            tokio::select! {
                result = work.as_mut() => return Ok(result),
                changed = changes.changed() => changed.map_err(|_| {
                    io::Error::new(io::ErrorKind::Interrupted, "proxy shutdown state closed")
                })?,
            }
        }
    }

    /// Start irreversible listener quiescence without imposing a flow timeout.
    /// A concurrent or previous process stop always wins over maintenance.
    #[cfg(any(feature = "management", test))]
    pub(crate) fn request_quiesce(&self) -> bool {
        self.graceful_shutdown.send_if_modified(|state| {
            if *state != Shutdown::Active {
                return false;
            }
            *state = Shutdown::Draining;
            true
        })
    }

    pub(crate) fn is_quiescing(&self) -> bool {
        #[cfg(any(feature = "management", test))]
        {
            *self.graceful_shutdown.borrow() == Shutdown::Draining
        }
        #[cfg(not(any(feature = "management", test)))]
        {
            false
        }
    }

    /// Observe the retained request when a listener completes between polls of
    /// the supervisor's shutdown and completion futures.
    #[cfg(feature = "management")]
    pub(crate) fn is_graceful_shutdown_requested(&self) -> bool {
        *self.graceful_shutdown.borrow() != Shutdown::Active
    }

    /// Cold management observation of real process stop, distinct from an
    /// unbounded maintenance drain. This never changes the retained deadline.
    #[cfg(feature = "management")]
    pub(crate) fn is_stopping(&self) -> bool {
        matches!(*self.graceful_shutdown.borrow(), Shutdown::Stopping { .. })
    }

    /// Requests graceful shutdown without waiting for a process signal.
    pub(crate) fn request_graceful_shutdown(&self) {
        self.stop_at(Instant::now() + super::CONNECTION_DRAIN_TIMEOUT);
    }

    fn stop_at(&self, deadline: Instant) {
        self.graceful_shutdown.send_if_modified(|state| {
            if matches!(*state, Shutdown::Stopping { .. }) {
                return false;
            }
            *state = Shutdown::Stopping { deadline };
            true
        });
    }

    /// Use the same production transition with a short deterministic deadline.
    #[cfg(test)]
    pub(crate) fn request_shutdown_at(&self, deadline: Instant) {
        self.stop_at(deadline);
    }

    /// Waits for a process shutdown signal and then requests graceful shutdown.
    pub(super) async fn graceful_shutdown(self) {
        match shutdown_signal().await {
            Ok(signal) => tracing::info!(signal, "received graceful shutdown signal"),
            Err(error) => tracing::warn!(%error, "failed to listen for shutdown signal"),
        }
        self.request_graceful_shutdown();
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;

    tokio::select! {
        received = interrupt.recv() => signal_name(received, "SIGINT"),
        received = terminate.recv() => signal_name(received, "SIGTERM"),
    }
}

#[cfg(unix)]
fn signal_name(received: Option<()>, name: &'static str) -> std::io::Result<&'static str> {
    received
        .map(|()| name)
        .ok_or_else(|| std::io::Error::other(format!("{name} signal stream closed")))
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("Ctrl+C")
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Waker},
    };

    use super::*;

    fn assert_pending(future: std::pin::Pin<&mut impl Future>) {
        assert!(
            future
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }

    #[tokio::test]
    async fn wait_graceful_shutdown_returns_after_shutdown() {
        let handle = Handle::new();
        let waiter = handle.clone();
        let task = tokio::spawn(async move {
            waiter.wait_graceful_shutdown().await;
        });

        handle.request_graceful_shutdown();

        task.await.expect("waiter should finish");
    }

    #[tokio::test]
    async fn late_waiter_returns_after_shutdown() {
        let handle = Handle::new();
        handle.request_graceful_shutdown();

        handle.wait_graceful_shutdown().await;
    }

    #[tokio::test]
    async fn maintenance_wakes_acceptors_but_only_first_stop_sets_the_deadline() {
        let handle = Handle::new();
        assert!(handle.request_quiesce());
        assert!(!handle.request_quiesce());
        assert!(handle.is_quiescing());
        handle.wait_graceful_shutdown().await;
        let mut stopping = std::pin::pin!(handle.wait_stopping());
        assert_pending(stopping.as_mut());
        let deadline = Instant::now() + Duration::from_secs(1);
        handle.request_shutdown_at(deadline);
        stopping.await;
        assert!(!handle.is_quiescing());
        assert!(!handle.request_quiesce());
        handle.request_graceful_shutdown();
        handle.request_shutdown_at(Instant::now());
        assert_eq!(
            *handle.graceful_shutdown.borrow(),
            Shutdown::Stopping { deadline }
        );
    }

    #[tokio::test]
    async fn phase_changes_keep_one_in_progress_future_and_outer_cancellation_drops_it_once() {
        struct Owned(Arc<AtomicUsize>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let handle = Handle::new();
        let starts = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let work_starts = starts.clone();
            let work_drops = drops.clone();
            let work = async move {
                work_starts.fetch_add(1, Ordering::SeqCst);
                let _owner = Owned(work_drops);
                pending::<()>().await;
            };
            let mut draining = std::pin::pin!(handle.wait_for_drain(work, Duration::ZERO));
            assert_pending(draining.as_mut());
            handle.request_quiesce();
            assert_pending(draining.as_mut());
            handle.request_shutdown_at(Instant::now() + Duration::from_secs(1));
            assert_pending(draining.as_mut());
            assert_eq!(starts.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drain_wait_has_no_maintenance_timer_and_grace_uses_the_original_stop_deadline() {
        let handle = Handle::new();
        handle.request_quiesce();
        let mut draining = std::pin::pin!(handle.wait_for_drain(pending::<()>(), Duration::ZERO));
        assert_pending(draining.as_mut());
        let deadline = Instant::now() - Duration::from_secs(2);
        handle.request_shutdown_at(deadline);
        assert_eq!(draining.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
        handle.request_graceful_shutdown();
        assert_eq!(
            handle
                .wait_for_drain(pending::<()>(), Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut,
            "cleanup grace is added to the original deadline, not a new now"
        );
        let mut reaping =
            std::pin::pin!(handle.wait_for_drain(pending::<()>(), Duration::from_secs(5)));
        assert_pending(reaping.as_mut());
        assert_eq!(
            *handle.graceful_shutdown.borrow(),
            Shutdown::Stopping { deadline }
        );
        // Already-completed cleanup can still return at an expired deadline.
        assert_eq!(
            handle
                .wait_for_drain(async { 7 }, Duration::ZERO)
                .await
                .unwrap(),
            7
        );
    }
}
