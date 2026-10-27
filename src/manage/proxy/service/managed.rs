//! Native orchestration for persisted Web service intents. The worker that
//! actually owns Running also owns configuration application and its receipt;
//! neither a detached HTTP task nor a timer can start a second listener group.

use super::*;
use crate::manage::{policy::Coordinator, proxy::settings, traffic};

/// Already-owned node choices, not request-supplied paths or TLS credentials.
/// The fixed protected TCP ports prevent proxy listeners from claiming the
/// management/node/challenge listeners through socket reuse.
pub(in crate::manage) struct Managed {
    pub(super) policy: Arc<Coordinator>,
    traffic: traffic::Handle,
    tls: settings::Tls,
    profile: crate::ebpf::Config,
    protected_tcp_ports: Vec<u16>,
    node_id: String,
    restored: bool,
    #[cfg(test)]
    pub(in crate::manage) ephemeral: bool,
}

impl Managed {
    pub(in crate::manage) fn new(
        policy: Arc<Coordinator>,
        traffic: traffic::Handle,
        tls: settings::Tls,
        profile: crate::ebpf::Config,
        node_id: String,
        protected_tcp_ports: Vec<u16>,
    ) -> io::Result<Self> {
        if !store::valid_id(&node_id) || protected_tcp_ports.len() > 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid managed service ownership",
            ));
        }
        Ok(Self {
            policy,
            traffic,
            tls,
            profile,
            node_id,
            protected_tcp_ports,
            restored: false,
            #[cfg(test)]
            ephemeral: false,
        })
    }

    fn validate(&self, configuration: &settings::Configuration) -> io::Result<()> {
        configuration.validate()?;
        if configuration.listeners.iter().any(|listener| {
            listener.protocol != super::super::Protocol::Masque
                && self.protected_tcp_ports.contains(&listener.bind.port())
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy TCP port is reserved for node management",
            ));
        }
        Ok(())
    }

    fn run(
        &mut self,
        worker: &mut Worker,
        runtime: &tokio::runtime::Runtime,
        input: Option<(String, store::proxy_service::Request)>,
    ) -> io::Result<View> {
        let restoring = input.is_none();
        if restoring && self.restored {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service startup was already reconciled",
            ));
        }
        if !restoring && !self.restored {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "service startup is not ready",
            ));
        }
        let directory = self.policy.service_directory();
        let (saved, original) = if let Some((administrator, request)) = input {
            self.validate(&request.configuration)?;
            // Validate identity availability before saving an enable intent.
            // Stop remains possible even if the normal certificate expired.
            if request.enabled
                && request.configuration.listeners.iter().any(|l| {
                    matches!(
                        l.protocol,
                        super::super::Protocol::Https
                            | super::super::Protocol::Masque
                            | super::super::Protocol::Auto
                    )
                })
            {
                self.tls.identity()?;
            }
            let _permit = runtime.block_on(self.policy.service_writer())?;
            let gate = store::update_lock(directory)?;
            let (receipt, accepted) =
                store::proxy_service::accept(directory, &gate, &administrator, &request)?;
            if !accepted {
                return Ok(worker.state.borrow().clone());
            }
            (receipt.state.clone(), Some(receipt))
        } else {
            let _permit = runtime.block_on(self.policy.service_writer())?;
            let gate = store::update_lock(directory)?;
            store::proxy_service::interrupt(directory, &gate)?;
            (store::proxy_service::read(directory)?, None)
        };
        let attempt = self.transition(worker, runtime, &saved, original.as_ref());
        if restoring {
            self.restored = true;
        }
        if let Some(original) = original {
            let _permit = runtime.block_on(self.policy.service_writer())?;
            let gate = store::update_lock(directory)?;
            store::proxy_service::finish(
                directory,
                &gate,
                &original,
                if attempt.is_ok() {
                    store::proxy_service::Outcome::Applied
                } else {
                    store::proxy_service::Outcome::Failed
                },
            )?;
        }
        // A known bind/start failure remains visible through the running API.
        // The exact original receipt is terminal Failed, never rolled back.
        if let Err(error) = attempt {
            if worker.running.is_none() {
                worker.failed(error.kind());
            } else {
                worker
                    .state
                    .send_modify(|view| view.failure = Some(error.kind()));
            }
            tracing::warn!(kind=?error.kind(),"managed service did not reach desired state");
        }
        Ok(worker.state.borrow().clone())
    }

    fn transition(
        &self,
        worker: &mut Worker,
        runtime: &tokio::runtime::Runtime,
        saved: &store::proxy_service::State,
        original: Option<&store::proxy_service::Receipt>,
    ) -> io::Result<()> {
        let directory = self.policy.service_directory();
        if saved.enabled && self.traffic.observation()?.active_run.is_none() {
            runtime.block_on(self.traffic.begin())?;
        }
        let _permit = runtime.block_on(self.policy.service_writer())?;
        let gate = store::update_lock(directory)?;
        if let Some(original) = original {
            // Owner/admin changes can overtake the earlier save, but cannot
            // overtake this bounded application while its writer is retained.
            store::admission::local_runtime_snapshot(
                directory,
                &original.administrator_id,
                Some(&store::admission::Assertion {
                    node_id: self.node_id.clone(),
                    epoch: original.owner_epoch,
                }),
            )?;
            if store::proxy_service::read(directory)? != *saved {
                return Err(store::proxy_service::Error::RevisionConflict.io());
            }
        }
        let configuration = saved.configuration.as_ref();
        if let Some(configuration) = configuration {
            self.validate(configuration)?;
        }
        let views = configuration.map_or(&[][..], |c| c.listeners.as_slice());
        let inventory = store::endpoints::Inventory::from_views(&self.node_id, views)?;
        store::endpoints::configure(directory, &gate, &inventory)?;
        self.policy.deactivate();
        let result = (|| -> io::Result<()> {
            let prepared = if saved.enabled {
                Some(
                    configuration
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "enabled service has no configuration",
                            )
                        })?
                        .prepare(&self.tls, self.profile.clone())?,
                )
            } else {
                None
            };
            #[cfg(test)]
            let prepared = prepared.map(|prepared| {
                if self.ephemeral {
                    crate::manage::proxy::tests::ephemeral(prepared)
                } else {
                    prepared
                }
            });
            let generation = worker.state.borrow().generation;
            worker.apply(runtime, generation, prepared)?;
            worker
                .state
                .send_modify(|view| view.endpoints = views.to_vec());
            if saved.enabled {
                self.policy.service_activate(&gate)?;
            }
            worker
                .state
                .send_modify(|view| view.configuration_revision = Some(saved.revision));
            Ok(())
        })();
        if let Err(error) = result {
            self.policy.deactivate();
            let cleanup = worker.reap(false);
            let error = cleanup.err().unwrap_or(error);
            worker.state.send_modify(|view| {
                view.endpoints = views.to_vec();
                view.certificates = Certificates::default();
            });
            worker.failed(error.kind());
            return Err(error);
        }
        Ok(())
    }
}

impl Worker {
    pub(super) fn configure(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        input: Option<(String, store::proxy_service::Request)>,
    ) -> io::Result<View> {
        let mut managed = self.managed.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed configuration is not enabled",
            )
        })?;
        let result = managed.run(self, runtime, input);
        self.managed = Some(managed);
        result
    }
}
