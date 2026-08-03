//! Shared graceful shutdown state for proxy servers and connection tasks.

use tokio::sync::watch;

/// Shared handle for graceful server shutdown.
///
/// The state is retained by `watch`, so tasks that start waiting after shutdown
/// was requested still return immediately.
#[derive(Clone)]
pub(crate) struct Handle {
    graceful_shutdown: watch::Sender<bool>,
}

impl Handle {
    /// Creates a handle in the running state.
    pub(super) fn new() -> Self {
        let (graceful_shutdown, _) = watch::channel(false);
        Self { graceful_shutdown }
    }

    /// Waits until graceful shutdown is requested.
    pub(crate) async fn wait_graceful_shutdown(&self) {
        let mut graceful_shutdown = self.graceful_shutdown.subscribe();
        loop {
            if *graceful_shutdown.borrow() || graceful_shutdown.changed().await.is_err() {
                return;
            }
        }
    }

    /// Requests graceful shutdown without waiting for a process signal.
    pub(crate) fn request_graceful_shutdown(&self) {
        self.graceful_shutdown.send_replace(true);
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
    use super::*;

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
}
