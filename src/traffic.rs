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

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn counter() -> Arc<Counter> {
        Arc::new(Counter::new(Snapshot {
            upload: 0,
            download: 0,
            saturated: false,
        }))
    }

    #[test]
    fn counters_remain_monotonic_and_keep_saturation_on_restore() {
        let counter = Counter::new(Snapshot {
            upload: u64::MAX - 2,
            download: 7,
            saturated: false,
        });
        counter.add(Direction::Upload, 2);
        assert!(!counter.snapshot().saturated);
        counter.add(Direction::Upload, 1);
        counter.add(Direction::Download, 3);
        assert_eq!(
            counter.snapshot(),
            Snapshot {
                upload: u64::MAX,
                download: 10,
                saturated: true
            }
        );
        let restored = Counter::new(counter.snapshot());
        restored.add(Direction::Upload, 0);
        assert_eq!(restored.snapshot(), counter.snapshot());
    }

    #[test]
    fn shared_series_does_not_lose_concurrent_direction_updates() {
        let counter = counter();
        std::thread::scope(|scope| {
            for direction in [Direction::Upload, Direction::Download] {
                for _ in 0..4 {
                    let meter = Meter::new(counter.clone(), direction);
                    scope.spawn(move || {
                        for _ in 0..1024 {
                            meter.add(3);
                        }
                    });
                }
            }
        });
        assert_eq!(
            counter.snapshot(),
            Snapshot {
                upload: 12_288,
                download: 12_288,
                saturated: false,
            }
        );
    }

    #[test]
    fn secondary_pool_is_a_separate_group_and_alias_does_not_double_count() {
        let primary = counter();
        let pool = counter();
        Meter::new(primary.clone(), Direction::Upload)
            .with_secondary(Some(pool.clone()))
            .add(7);
        assert_eq!(primary.snapshot().upload, 7);
        assert_eq!(pool.snapshot().upload, 7);
        Meter::new(primary.clone(), Direction::Download)
            .with_secondary(Some(primary.clone()))
            .add(3);
        assert_eq!(primary.snapshot().download, 3);
        assert_eq!(pool.snapshot().download, 0);
    }
}
