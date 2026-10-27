//! Bounded FIFO exclusion for one configured peer. Waiting does not reserve a
//! network or command slot, so a hot peer cannot occupy another peer's budget.
//! Exclusive observation and delivery prevent late snapshots being published as
//! a target rollback. Actual blocking publishers retain the same Claim.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::{busy, unavailable};

pub(super) const MAX_PEERS: usize = 128;
pub(super) const MAX_WAITERS: usize = 32;
pub(super) const MAX_PEER_WAITERS: usize = 8;
// Observations cannot fill the final positions needed for a durable command to
// join the same FIFO. This reserves waiting space, not execution priority.
const MAX_OBSERVERS: usize = MAX_WAITERS - 2;
const MAX_PEER_OBSERVERS: usize = MAX_PEER_WAITERS - 1;
pub(super) const WAIT_TIMEOUT: Duration = Duration::from_secs(1);

/// Weak registration keeps a single gate while any owner or waiter exists,
/// without retaining every historical target after its work finishes.
pub(super) struct Admission {
    peers: Mutex<HashMap<String, Weak<Peer>>>,
    waiting: Semaphore,
    observers: Semaphore,
}

/// The execution permit is separate from this peer's pending-position budget.
/// Acquiring a Claim returns the pending position before work begins.
struct Peer {
    owner: Arc<Semaphore>,
    waiting: Semaphore,
    observers: Semaphore,
}

/// May be shared with a real blocking store worker. Release the semaphore before
/// the last Peer reference: otherwise a replacement gate could be registered
/// while the old claim still owns its permit. Fields drop in declaration order.
pub(super) struct Claim {
    _permit: OwnedSemaphorePermit,
    _peer: Arc<Peer>,
}

impl Admission {
    pub(super) fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            waiting: Semaphore::new(MAX_WAITERS),
            observers: Semaphore::new(MAX_OBSERVERS),
        }
    }

    /// Callers supply an already-validated peer ID. At most 128 live gates are
    /// registered; stale Weak entries are removed before counting the bound.
    fn peer(&self, id: &str) -> io::Result<Arc<Peer>> {
        let mut peers = self.peers.lock().map_err(|_| unavailable())?;
        if let Some(peer) = peers.get(id).and_then(Weak::upgrade) {
            return Ok(peer);
        }
        peers.retain(|_, peer| peer.strong_count() != 0);
        if peers.len() >= MAX_PEERS {
            return Err(busy());
        }
        let peer = Arc::new(Peer {
            owner: Arc::new(Semaphore::new(1)),
            waiting: Semaphore::new(MAX_PEER_WAITERS),
            observers: Semaphore::new(MAX_PEER_OBSERVERS),
        });
        peers.insert(id.to_owned(), Arc::downgrade(&peer));
        Ok(peer)
    }

    /// An uncontended peer enters immediately. Contention waits FIFO for at most
    /// one second. Observers use at most seven waiting positions per peer and
    /// 30 globally, leaving one/two positions for commands. All share one FIFO;
    /// a command cannot overtake an already admitted observer. Full queues or
    /// expiry return WouldBlock before SQL/network work is submitted.
    /// Dropping this future loses its place and releases all waiting budgets;
    /// dropping a returned Claim releases only when all its actual owners end.
    pub(super) async fn acquire(&self, id: &str) -> io::Result<Claim> {
        self.acquire_inner(id, false).await
    }

    /// Commands share the same deadline and FIFO, but may also use the reserved
    /// waiting positions. The total remains eight per peer and 32 globally.
    pub(super) async fn acquire_command(&self, id: &str) -> io::Result<Claim> {
        self.acquire_inner(id, true).await
    }

    async fn acquire_inner(&self, id: &str, command: bool) -> io::Result<Claim> {
        let peer = self.peer(id)?;
        match peer.owner.clone().try_acquire_owned() {
            Ok(permit) => {
                return Ok(Claim {
                    _permit: permit,
                    _peer: peer,
                });
            }
            Err(TryAcquireError::NoPermits) => {}
            Err(TryAcquireError::Closed) => return Err(unavailable()),
        }
        // Reject excess observers before touching shared positions. Reversing
        // this order would let even a rejected read transiently take a command's
        // reserved position and make a concurrent command spuriously busy.
        let _observers = if command {
            None
        } else {
            Some((
                self.observers.try_acquire().map_err(|_| busy())?,
                peer.observers.try_acquire().map_err(|_| busy())?,
            ))
        };
        let _global = self.waiting.try_acquire().map_err(|_| busy())?;
        let _local = peer.waiting.try_acquire().map_err(|_| busy())?;
        // Tokio's semaphore hands released permits to queued waiters before a
        // later try_acquire can take one. Do not replace this with timed retry.
        let permit = tokio::time::timeout(WAIT_TIMEOUT, peer.owner.clone().acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| unavailable())?;
        // Return shared positions before observer reservations, maintaining the
        // same reserved-space invariant while another thread enters the gate.
        drop((_local, _global, _observers));
        Ok(Claim {
            _permit: permit,
            _peer: peer,
        })
    }

    #[cfg(test)]
    pub(super) fn try_claim(&self, id: &str) -> io::Result<Claim> {
        let peer = self.peer(id)?;
        let permit = peer.owner.clone().try_acquire_owned().map_err(|_| busy())?;
        Ok(Claim {
            _permit: permit,
            _peer: peer,
        })
    }

    #[cfg(test)]
    pub(super) fn is_active(&self, id: &str) -> io::Result<bool> {
        let peers = self.peers.lock().map_err(|_| unavailable())?;
        Ok(peers
            .get(id)
            .and_then(Weak::upgrade)
            .is_some_and(|peer| peer.owner.available_permits() == 0))
    }

    #[cfg(test)]
    pub(super) fn try_is_active(&self, id: &str) -> Option<bool> {
        let peers = self.peers.try_lock().ok()?;
        Some(
            peers
                .get(id)
                .and_then(Weak::upgrade)
                .is_some_and(|peer| peer.owner.available_permits() == 0),
        )
    }
}
