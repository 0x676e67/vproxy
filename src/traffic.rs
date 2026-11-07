//! Managed proxy payload accepted by a forwarding transport, not network or
//! application delivery. Protocol framing must stay outside these counters.
//!
//! One credential/protocol series owns a shared counter. The registry keeps a
//! strong reference until its final checkpoint, independently of active flows;
//! a successful write must not disappear when a task fails or is cancelled.

mod data;
mod io;

pub(crate) use data::Data;
pub(crate) use io::Io;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Direction is relative to the proxy client, independent of socket ownership.
#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Upload,
    Download,
}

/// Monotonic process-local view of one stable credential/protocol series.
///
/// The two directions are sampled separately; this is not a transactional pair
/// or a wire-level acknowledgement. Saturation is sticky and never wraps to zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) upload: u64,
    pub(crate) download: u64,
    pub(crate) saturated: bool,
}

impl Snapshot {
    /// Combine disjoint payload groups without wrapping either direction or
    /// clearing a previous lower-bound marker. This does not add wire overhead.
    pub(crate) fn sum(self, other: Self) -> Self {
        let upload = self.upload.checked_add(other.upload);
        let download = self.download.checked_add(other.download);
        Self {
            upload: upload.unwrap_or(u64::MAX),
            download: download.unwrap_or(u64::MAX),
            saturated: self.saturated || other.saturated || upload.is_none() || download.is_none(),
        }
    }
}

/// Directly held by the bounded registry and admitted flows. No identity lookup,
/// lock, allocation, database operation or peer request occurs while adding bytes.
pub(crate) struct Counter {
    upload: AtomicU64,
    download: AtomicU64,
    saturated: AtomicBool,
}

impl Counter {
    /// Seed from committed absolute totals, or zero for a new series. A previous
    /// saturation remains visible after restart rather than claiming precision.
    pub(crate) fn new(snapshot: Snapshot) -> Self {
        Self {
            upload: AtomicU64::new(snapshot.upload),
            download: AtomicU64::new(snapshot.download),
            saturated: AtomicBool::new(snapshot.saturated),
        }
    }

    /// Observe cumulative lower bounds without resetting them. Checkpointing a
    /// snapshot must not discard writes that race with a successful DB commit.
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            upload: self.upload.load(Ordering::Acquire),
            download: self.download.load(Ordering::Acquire),
            saturated: self.saturated.load(Ordering::Acquire),
        }
    }

    /// Record only bytes already reported accepted by a write/send operation.
    /// Overflow is explicit; unsigned wrapping would turn heavy usage into zero.
    pub(crate) fn add(&self, direction: Direction, length: usize) {
        if length == 0 {
            return;
        }
        let amount = u64::try_from(length).unwrap_or_else(|_| {
            self.saturated.store(true, Ordering::Relaxed);
            u64::MAX
        });
        let counter = match direction {
            Direction::Upload => &self.upload,
            Direction::Download => &self.download,
        };
        // Counts only increase, so once addition would overflow it remains an
        // overflow after any failed CAS. Release publishes the preceding sticky
        // flag before a snapshot acquires that numeric update. This still is
        // not an atomic observation of both directions at one instant.
        let _ = counter.try_update(Ordering::Release, Ordering::Relaxed, |previous| {
            Some(previous.checked_add(amount).unwrap_or_else(|| {
                self.saturated.store(true, Ordering::Relaxed);
                u64::MAX
            }))
        });
    }
}

/// Small direction-bound handle retained by an in-flight buffer or writer.
/// It contains no secret, policy snapshot, display name or database connection.
#[derive(Clone)]
pub(crate) struct Meter {
    counter: Arc<Counter>,
    secondary: Option<Arc<Counter>>,
    direction: Direction,
}

impl Meter {
    pub(crate) fn new(counter: Arc<Counter>, direction: Direction) -> Self {
        Self {
            counter,
            secondary: None,
            direction,
        }
    }

    /// Attribute the same accepted payload to a selected pool as a separate
    /// grouping. Node/user totals use only the primary credential series, not
    /// the sum of both views. An aliased handle must never count bytes twice.
    pub(crate) fn with_secondary(mut self, counter: Option<Arc<Counter>>) -> Self {
        self.secondary = counter.filter(|counter| !Arc::ptr_eq(counter, &self.counter));
        self
    }

    pub(crate) fn add(&self, length: usize) {
        self.counter.add(self.direction, length);
        if let Some(counter) = &self.secondary {
            counter.add(self.direction, length);
        }
    }
}
