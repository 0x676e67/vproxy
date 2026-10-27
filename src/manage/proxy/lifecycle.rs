//! Process-local listener control. Durable admission and authorisation remain
//! the coordinator's responsibility; this handle never owns a worker runtime.

use std::{
    fmt, io,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::server::Handle;

/// The administrator whose already-authorised request stopped new listeners.
/// These identifiers are retained for exact duplicate detection, not authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) enum DrainActor {
    Local {
        administrator_id: String,
    },
    Remote {
        controller_node_id: String,
        administrator_id: String,
    },
}

/// One explicit request bound to the current node, owner epoch and paused
/// policy revision. A process restart creates a different runtime namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct DrainIntent {
    pub(in crate::manage) node_id: String,
    pub(in crate::manage) request_id: String,
    pub(in crate::manage) epoch: u64,
    pub(in crate::manage) revision: u64,
    pub(in crate::manage) actor: DrainActor,
}

impl DrainIntent {
    fn validate(&self) -> io::Result<()> {
        let valid_id = super::super::store::valid_id;
        let actor_valid = match &self.actor {
            DrainActor::Local { administrator_id } => valid_id(administrator_id),
            DrainActor::Remote {
                controller_node_id,
                administrator_id,
            } => {
                valid_id(controller_node_id)
                    && controller_node_id != &self.node_id
                    && valid_id(administrator_id)
            }
        };
        if !valid_id(&self.node_id)
            || !valid_id(&self.request_id)
            || !actor_valid
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || self.revision == 0
            || self.revision > i64::MAX as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid proxy drain intent",
            ));
        }
        Ok(())
    }
}

/// Driver completion is distinct from destruction of its retained worker pool.
/// `Drained` confirms listener tasks finished, never `runtime_stopped`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Phase {
    Serving,
    Draining,
    Drained,
    Interrupted,
    Failed,
}

/// Non-secret runtime facts. API projections must validate their own wire
/// contract rather than serialise this internal state directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::manage) struct View {
    pub(in crate::manage) runtime_id: String,
    pub(in crate::manage) phase: Phase,
    pub(in crate::manage) intent: Option<DrainIntent>,
    /// The actual shared Handle has entered bounded process stop. A drain's
    /// retained phase/identity is unchanged; this is not a wire status field.
    pub(in crate::manage) stopping: bool,
}

/// Definitive process-local refusals; no filesystem or original driver message
/// is embedded in the error returned through an API boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manage) enum Error {
    RuntimeChanged,
    AlreadyDraining,
    Stopping,
}

impl Error {
    fn error(self) -> io::Error {
        io::Error::new(io::ErrorKind::AlreadyExists, self)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuntimeChanged => "proxy runtime changed",
            Self::AlreadyDraining => "proxy runtime already draining",
            Self::Stopping => "proxy runtime stopping",
        })
    }
}

impl std::error::Error for Error {}

struct State {
    phase: Phase,
    intent: Option<DrainIntent>,
}

struct Shared {
    runtime_id: String,
    handle: Handle,
    state: Mutex<State>,
}

/// Small cloneable control surface for one actual `Running`. It cannot start a
/// replacement runtime, change durable admission or release the author lease.
#[derive(Clone)]
pub(in crate::manage) struct Lifecycle(Arc<Shared>);

/// Entropy is obtained before worker construction. The private payload cannot
/// be forged by a caller or fail after attaching the real runtime handle.
pub(super) struct Identity(String);

impl Identity {
    pub(super) fn attach(self, handle: Handle) -> Lifecycle {
        Lifecycle(Arc::new(Shared {
            runtime_id: self.0,
            handle,
            state: Mutex::new(State {
                phase: Phase::Serving,
                intent: None,
            }),
        }))
    }
}

impl Lifecycle {
    /// Allocate one unpredictable, canonical runtime identifier. Entropy failure
    /// must happen before constructing workers; attachment is then infallible.
    pub(super) fn prepare() -> io::Result<Identity> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| io::Error::other("proxy runtime identity unavailable"))?;
        Ok(Identity(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Tests use their already-existing Tokio worker, not a new owned runtime.
    #[cfg(test)]
    pub(in crate::manage) fn new(handle: Handle) -> io::Result<Self> {
        Ok(Self::prepare()?.attach(handle))
    }

    fn state(&self) -> io::Result<MutexGuard<'_, State>> {
        self.0
            .state
            .lock()
            .map_err(|_| io::Error::other("proxy runtime state unavailable"))
    }

    fn view(&self, state: &State) -> View {
        View {
            runtime_id: self.0.runtime_id.clone(),
            phase: state.phase,
            intent: state.intent.clone(),
            stopping: self.0.handle.is_stopping(),
        }
    }

    /// Return a coherent cold-path observation. A poisoned state is unknown,
    /// never a synthetic serving/drained result.
    pub(in crate::manage) fn snapshot(&self) -> io::Result<View> {
        let state = self.state()?;
        Ok(self.view(&state))
    }

    /// Quiesce once after the coordinator has checked authorisation, ownership,
    /// CAS and applied admission. Exact duplicate intent is idempotent; another
    /// intent cannot adopt this drain. Process stop always remains irreversible.
    pub(in crate::manage) fn request(
        &self,
        runtime_id: &str,
        intent: DrainIntent,
    ) -> io::Result<View> {
        intent.validate()?;
        let mut state = self.state()?;
        if runtime_id != self.0.runtime_id {
            return Err(Error::RuntimeChanged.error());
        }
        if self.0.handle.is_stopping() {
            return Err(Error::Stopping.error());
        }
        if let Some(original) = &state.intent {
            return if original == &intent {
                Ok(self.view(&state))
            } else {
                Err(Error::AlreadyDraining.error())
            };
        }
        // The retained watch transition is atomic with respect to process stop.
        // Hold the state lock until the intent is installed so completion cannot
        // observe the quiesce without its corresponding request identity.
        if !self.0.handle.request_quiesce() {
            return Err(if self.0.handle.is_quiescing() {
                Error::AlreadyDraining
            } else {
                Error::Stopping
            }
            .error());
        }
        state.intent = Some(intent);
        state.phase = Phase::Draining;
        Ok(self.view(&state))
    }

    /// Record the single consumed listener result. Only an explicitly requested
    /// drain lets management remain online. Repeated calls cannot clear an
    /// earlier interruption/failure by supplying a later successful result.
    pub(in crate::manage) fn complete(&self, result: &io::Result<()>) -> io::Result<bool> {
        let mut state = self.state()?;
        if state.intent.is_none() {
            return Ok(false);
        }
        if state.phase == Phase::Draining {
            state.phase = match result {
                Ok(()) => Phase::Drained,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => Phase::Interrupted,
                Err(_) => Phase::Failed,
            };
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> DrainIntent {
        DrainIntent {
            node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            request_id: "AQEBAQEBAQEBAQEBAQEBAQ".into(),
            epoch: 1,
            revision: 2,
            actor: DrainActor::Local {
                administrator_id: "AgICAgICAgICAgICAgICAg".into(),
            },
        }
    }

    fn refusal(error: io::Error, expected: Error) {
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<Error>()),
            Some(&expected)
        );
    }

    #[tokio::test]
    async fn runtime_identity_exact_intent_and_monotonic_stop() {
        let handle = Handle::new();
        let control = Lifecycle::new(handle.clone()).unwrap();
        let initial = control.snapshot().unwrap();
        assert!(super::super::super::store::valid_id(&initial.runtime_id));
        assert_eq!(initial.phase, Phase::Serving);
        assert_eq!(initial.intent, None);
        assert!(!initial.stopping);
        let other = Lifecycle::new(Handle::new()).unwrap().snapshot().unwrap();
        assert_ne!(other.runtime_id, initial.runtime_id);
        refusal(
            control.request(&other.runtime_id, intent()).unwrap_err(),
            Error::RuntimeChanged,
        );
        assert!(!handle.is_graceful_shutdown_requested());
        let requested = control.request(&initial.runtime_id, intent()).unwrap();
        assert_eq!(requested.phase, Phase::Draining);
        assert!(!requested.stopping);
        assert!(handle.is_quiescing());
        assert_eq!(
            control
                .clone()
                .request(&initial.runtime_id, intent())
                .unwrap(),
            requested
        );
        let mut different = intent();
        different.revision += 1;
        refusal(
            control.request(&initial.runtime_id, different).unwrap_err(),
            Error::AlreadyDraining,
        );
        // A real process stop becomes visible without rewriting the maintenance
        // phase or intent. A repeated request cannot extend the first deadline.
        handle.request_shutdown_at(tokio::time::Instant::now() - std::time::Duration::from_secs(1));
        let stopped = control.snapshot().unwrap();
        assert_eq!(
            stopped,
            View {
                stopping: true,
                ..requested
            }
        );
        handle.request_graceful_shutdown();
        assert_eq!(control.snapshot().unwrap(), stopped);
        assert_eq!(
            handle
                .wait_for_drain(std::future::pending::<()>(), std::time::Duration::ZERO)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        refusal(
            control.request(&initial.runtime_id, intent()).unwrap_err(),
            Error::Stopping,
        );
        assert!(!handle.is_quiescing());
    }

    #[tokio::test]
    async fn completion_requires_intent_and_preserves_first_terminal_fact() {
        for (kind, phase) in [
            (None, Phase::Drained),
            (Some(io::ErrorKind::TimedOut), Phase::Interrupted),
            (Some(io::ErrorKind::PermissionDenied), Phase::Failed),
        ] {
            let control = Lifecycle::new(Handle::new()).unwrap();
            assert!(!control.complete(&Ok(())).unwrap());
            assert_eq!(control.snapshot().unwrap().phase, Phase::Serving);
            let id = control.snapshot().unwrap().runtime_id;
            control.request(&id, intent()).unwrap();
            let result = kind.map_or(Ok(()), |kind| Err(io::Error::new(kind, "driver fixture")));
            assert!(control.complete(&result).unwrap());
            let completed = control.snapshot().unwrap();
            assert_eq!(completed.phase, phase);
            assert_eq!(completed.intent, Some(intent()));
            assert!(control.complete(&Ok(())).unwrap());
            assert_eq!(control.snapshot().unwrap(), completed);
            assert_eq!(control.request(&id, intent()).unwrap(), completed);
        }
    }

    #[tokio::test]
    async fn invalid_intent_or_unowned_quiesce_cannot_claim_a_drain() {
        let handle = Handle::new();
        let control = Lifecycle::new(handle.clone()).unwrap();
        let id = control.snapshot().unwrap().runtime_id;
        let mut invalid = intent();
        invalid.epoch = 0;
        assert_eq!(
            control.request(&id, invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!handle.is_graceful_shutdown_requested());
        let mut remote = intent();
        remote.actor = DrainActor::Remote {
            controller_node_id: remote.node_id.clone(),
            administrator_id: "AgICAgICAgICAgICAgICAg".into(),
        };
        assert_eq!(
            control.request(&id, remote).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        handle.request_quiesce();
        refusal(
            control.request(&id, intent()).unwrap_err(),
            Error::AlreadyDraining,
        );
        assert!(control.snapshot().unwrap().intent.is_none());
    }
}
