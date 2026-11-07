//! Pingora runtime management for proxy servers.

use std::{
    any::Any,
    future::Future,
    io,
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::mpsc,
    time::Duration,
};

use futures_util::FutureExt;
use tokio::sync::oneshot;

use super::Handle;
use crate::Result;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Process-level no-steal runtime.
pub(crate) struct Runtime(pingora_runtime::Runtime);

/// One authoritative server result plus a cancellation-safe async notification.
/// The result is not duplicated: either the supervisor or synchronous teardown
/// receives it. A canceled wait keeps both channels available for teardown.
pub(crate) struct Completion {
    result: mpsc::Receiver<Result<()>>,
    notified: oneshot::Receiver<()>,
    received: bool,
}

impl Completion {
    /// Wait for a server result without blocking another runtime's worker.
    /// Calling again after a result was delivered is an API misuse error.
    #[cfg(feature = "management")]
    pub(crate) async fn finished(&mut self) -> Result<()> {
        if self.received {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy result already received",
            )
            .into());
        }
        let _ = (&mut self.notified).await;
        self.received = true;
        self.result.try_recv().unwrap_or_else(|_| {
            Err(io::Error::new(io::ErrorKind::Interrupted, "proxy result channel closed").into())
        })
    }

    /// Bounded synchronous teardown after the async supervisor has returned.
    /// A result already consumed there is not delivered a second time.
    #[cfg(feature = "management")]
    pub(crate) fn wait_timeout(&mut self, timeout: Duration) -> Result<()> {
        if self.received {
            return Ok(());
        }
        let result = self.result.recv_timeout(timeout).unwrap_or_else(|error| {
            let kind = match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::Interrupted,
            };
            Err(io::Error::new(kind, "proxy runtime did not report completion").into())
        });
        self.received = true;
        result
    }

    fn wait(self) -> Result<()> {
        if self.received {
            return Ok(());
        }
        // Legacy run deliberately blocks until its server/signal lifecycle ends.
        // Consume the notification too so non-management builds retain no
        // unused async-only state.
        drop(self.notified);
        self.result.recv().unwrap_or_else(|_| {
            Err(io::Error::new(io::ErrorKind::Interrupted, "proxy result channel closed").into())
        })
    }
}

impl Runtime {
    /// Creates a no-steal runtime with the selected worker count.
    pub(crate) fn new(threads: NonZeroUsize) -> Self {
        Self(pingora_runtime::Runtime::new_no_steal(
            threads.get(),
            env!("CARGO_PKG_NAME"),
        ))
    }

    /// Initialize workers and capture only this instance's public Tokio handles.
    /// Pingora's process-global `current_handle` cache is unsuitable for repeated
    /// or simultaneous runtimes: its ThreadLocal slots survive reused thread IDs.
    /// https://github.com/cloudflare/pingora/blob/719ef6cd54e40b530127751bab6c1afc5ae815a8/pingora-runtime/src/lib.rs#L130-L146
    pub(crate) fn handle(&self) -> io::Result<Handle> {
        let workers = catch_unwind(AssertUnwindSafe(|| match &self.0 {
            pingora_runtime::Runtime::NoSteal(runtime) => (0..runtime.threads())
                .map(|index| runtime.get_runtime_at(index).clone())
                .collect(),
            pingora_runtime::Runtime::Steal(runtime) => vec![runtime.handle().clone()],
        }))
        .map_err(|_| io::Error::other("cannot initialize proxy runtime workers"))?;
        Handle::with_workers(workers)
    }

    /// Starts one supervised future without installing signals or blocking the
    /// caller. The runtime must stay owned by the synchronous outer runner until
    /// this receiver completes, then be destroyed with [`Self::shutdown`].
    ///
    /// Pingora initializes its workers lazily inside `get_handle` and its API
    /// panics on OS thread/runtime creation failure. Convert that boundary into
    /// an ordinary startup error; panics inside the future are also reported.
    pub(crate) fn spawn<Fut>(&self, future: Fut) -> io::Result<Completion>
    where
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let runtime = catch_unwind(AssertUnwindSafe(|| self.0.get_handle().clone()))
            .map_err(|_| io::Error::other("cannot initialize proxy runtime workers"))?;
        let (finish, result) = mpsc::channel();
        let (notify, notified) = oneshot::channel();
        runtime.spawn(async move {
            let result = AssertUnwindSafe(future)
                .catch_unwind()
                .await
                .unwrap_or_else(server_panic_error);
            // Dropping the supervisor is cancellation, not a reason to retain
            // the completed task or log any future result payload.
            let _ = finish.send(result);
            let _ = notify.send(());
        });
        Ok(Completion {
            result,
            notified,
            received: false,
        })
    }

    /// Joins the Pingora worker threads. This is blocking and must be called
    /// outside every async runtime, after graceful server completion.
    pub(crate) fn shutdown(self) {
        self.0.shutdown_timeout(SHUTDOWN_TIMEOUT);
    }

    /// Runs the server with a shared shutdown handle and blocks until it returns.
    pub(crate) fn block_on<F, Fut>(self, serve: F) -> Result<()>
    where
        F: FnOnce(Handle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handle = self.handle()?;
        // A no-steal Pingora runtime selects a worker for each new task.
        // https://docs.rs/pingora-runtime/0.8.1/src/pingora_runtime/lib.rs.html#63-72
        let task_handle = handle.clone();
        let finished = self.spawn(async move { serve(task_handle).await })?;
        let signal = self.0.get_handle().spawn(handle.graceful_shutdown());

        let result = finished.wait();
        signal.abort();
        self.shutdown();
        result
    }
}

fn server_panic_error(payload: Box<dyn Any + Send>) -> Result<()> {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("server task panicked");

    Err(io::Error::other(format!("server task panicked: {message}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simultaneous_runtime_dispatch_survives_a_sibling_shutdown() {
        let first = Runtime::new(NonZeroUsize::new(1).expect("one worker"));
        let second = Runtime::new(NonZeroUsize::new(1).expect("one worker"));
        let first_handle = first.handle().expect("first worker pool");
        let second_handle = second.handle().expect("second worker pool");
        assert_ne!(
            first_handle.runtime_handle().id(),
            second_handle.runtime_handle().id()
        );
        first
            .spawn(async move {
                assert_eq!(
                    first_handle.runtime_handle().id(),
                    tokio::runtime::Handle::current().id()
                );
                Ok(())
            })
            .expect("first task")
            .wait()
            .expect("first result");
        first.shutdown();
        second
            .spawn(async move {
                assert_eq!(
                    second_handle.runtime_handle().id(),
                    tokio::runtime::Handle::current().id()
                );
                second_handle
                    .runtime_handle()
                    .spawn(async { 42 })
                    .await
                    .map_err(io::Error::other)?;
                Ok(())
            })
            .expect("second task")
            .wait()
            .expect("second result after first runtime stopped");
        second.shutdown();
    }
}
