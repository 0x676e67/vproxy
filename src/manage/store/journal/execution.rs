//! Cooperative work budgets on the private Source connection, not process-wide
//! SQLite limits. Session owns pre-update; this guard uses only progress_handler.
//! It never grants COMMIT, performs SQL in a callback or changes a global clock.

use super::*;
use std::time::{Duration, Instant};

/// Approximate VM work is sampled once per 4096 instructions. Short statements
/// may not invoke the hook; explicit checkpoints also check monotonic elapsed
/// time. This is not a total CPU, Session-heap or blocking-filesystem deadline.
const INTERVAL: i32 = 4096;

#[derive(Clone, Copy)]
/// One capture/replay phase, excluding the later witness wait and COMMIT. Raw
/// mutations are interactive; history scans and offline full-DB seals receive
/// larger ceilings. These initial refusal thresholds are not capacity SLOs.
pub(super) struct Limits {
    /// Callback quanta charged in INTERVAL-sized units, not an exact aggregate
    /// count across short SQL statements or Rust/file work between statements.
    pub(super) steps: u64,
    /// Monotonic elapsed ceiling, checked by progress and explicit checkpoints.
    pub(super) elapsed: Duration,
}
impl Limits {
    pub(super) const MUTATION: Self = Self {
        steps: 1_000_000_000,
        elapsed: Duration::from_secs(30),
    };
    pub(super) const HISTORY: Self = Self {
        steps: 5_000_000_000,
        elapsed: Duration::from_secs(180),
    };
    pub(super) const SNAPSHOT: Self = Self {
        steps: 5_000_000_000,
        elapsed: Duration::from_secs(300),
    };
}

/// Install after constructing the owned transaction, so this guard drops first
/// and clears interruption before that transaction's rollback. Explicit finish
/// must likewise precede transferring/committing the transaction. The dedicated
/// connection has no other progress handler; none is replaced or restored.
pub(super) struct Execution<'a> {
    connection: &'a Connection,
    started: Instant,
    limits: Limits,
    exhausted: Arc<AtomicBool>,
    installed: bool,
}
impl<'a> Execution<'a> {
    pub(super) fn new(connection: &'a Connection, limits: Limits) -> io::Result<Self> {
        let started = Instant::now();
        let exhausted = Arc::new(AtomicBool::new(false));
        let stop = exhausted.clone();
        let mut remaining = limits.steps;
        connection
            .progress_handler(
                INTERVAL,
                Some(move || {
                    let within_steps = match remaining.checked_sub(INTERVAL as u64) {
                        Some(left) if left != 0 => {
                            remaining = left;
                            true
                        }
                        _ => false,
                    };
                    if !within_steps || started.elapsed() >= limits.elapsed {
                        stop.store(true, Ordering::Release);
                        true
                    } else {
                        false
                    }
                }),
            )
            .map_err(|e| sqlite_error("cannot install source execution budget", e))?;
        Ok(Self {
            connection,
            started,
            limits,
            exhausted,
            installed: true,
        })
    }

    /// Poison is sticky even when trusted code catches SQLITE_INTERRUPT. This
    /// rejects before dispatch; post-dispatch replay failures remain uncertain
    /// in the original driver and may only reconcile that retained intent.
    pub(super) fn check(&self) -> io::Result<()> {
        if self.exhausted.load(Ordering::Acquire) || self.started.elapsed() >= self.limits.elapsed {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "source execution budget exhausted",
            ));
        }
        Ok(())
    }

    /// Remove the hook before returning any candidate or allowing rollback.
    /// Removal failure cannot authorize a candidate; Drop retries only removal.
    pub(super) fn finish(mut self) -> io::Result<()> {
        self.clear()?;
        self.check()
    }
    fn clear(&mut self) -> io::Result<()> {
        if self.installed {
            self.connection
                .progress_handler(0, None::<fn() -> bool>)
                .map_err(|e| sqlite_error("cannot remove source execution budget", e))?;
            self.installed = false;
        }
        Ok(())
    }
}
impl Drop for Execution<'_> {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

#[cfg(test)]
mod tests {
    //! Real SQLite progress/Session/commit callbacks. Small private limits exercise
    //! exhaustion without sleeps, changing clocks or weakening production budgets.
    use super::*;

    const QUERY: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000) SELECT sum(x) FROM n";

    fn connection() -> io::Result<Connection> {
        let c = Connection::open_in_memory().map_err(io::Error::other)?;
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT; INSERT INTO t VALUES(1,'original');").map_err(io::Error::other)?;
        Ok(c)
    }
    fn value(c: &Connection) -> io::Result<String> {
        c.query_row("SELECT value FROM t WHERE id=1", [], |r| r.get(0))
            .map_err(io::Error::other)
    }
    fn tiny() -> Limits {
        Limits {
            steps: 8192,
            elapsed: Duration::from_secs(60),
        }
    }
    fn sum(c: &Connection) -> rusqlite::Result<i64> {
        c.query_row(QUERY, [], |r| r.get(0))
    }

    #[test]
    fn interrupted_sql_is_sticky_even_when_caught_and_finish_removes_the_hook() -> io::Result<()> {
        let mut c = connection()?;
        let tx = c.transaction().map_err(io::Error::other)?;
        let execution = Execution::new(&tx, tiny())?;
        tx.execute("UPDATE t SET value='candidate'", [])
            .map_err(io::Error::other)?;
        assert!(sum(&tx).is_err());
        assert_eq!(
            execution.check().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            execution.finish().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        tx.rollback().map_err(io::Error::other)?;
        assert_eq!(value(&c)?, "original");
        assert_eq!(sum(&c).map_err(io::Error::other)?, 1_250_025_000);
        Ok(())
    }

    #[test]
    fn checkpoint_detects_elapsed_work_without_a_progress_call_and_does_not_change_clocks()
    -> io::Result<()> {
        let c = connection()?;
        let execution = Execution::new(
            &c,
            Limits {
                steps: u64::MAX,
                elapsed: Duration::ZERO,
            },
        )?;
        assert_eq!(
            execution.check().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            execution.finish().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(sum(&c).map_err(io::Error::other)?, 1_250_025_000);
        Ok(())
    }

    #[test]
    fn early_return_drops_interruption_before_transaction_rollback() -> io::Result<()> {
        let mut c = connection()?;
        fn rejected(c: &mut Connection) -> io::Result<()> {
            let tx = c.transaction().map_err(io::Error::other)?;
            let execution = Execution::new(&tx, tiny())?;
            tx.execute("UPDATE t SET value='candidate'", [])
                .map_err(io::Error::other)?;
            let _caught = sum(&tx);
            execution.check()
        }
        assert_eq!(
            rejected(&mut c).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert!(c.is_autocommit());
        assert_eq!(value(&c)?, "original");
        assert_eq!(sum(&c).map_err(io::Error::other)?, 1_250_025_000);
        Ok(())
    }

    #[test]
    fn progress_budget_coexists_with_session_and_never_grants_the_commit_veto() -> io::Result<()> {
        let c = connection()?;
        let _veto = super::super::Veto::new(&c)?;
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        let execution = Execution::new(&tx, Limits::MUTATION)?;
        let mut session = Session::new(&c).map_err(io::Error::other)?;
        session.attach(Some("t")).map_err(io::Error::other)?;
        tx.execute("UPDATE t SET value='candidate'", [])
            .map_err(io::Error::other)?;
        let payload = super::super::replay::session_payload(&mut session)?;
        assert!(!payload.is_empty());
        drop(session);
        execution.finish()?;
        assert!(tx.commit().is_err());
        assert_eq!(value(&c)?, "original");
        Ok(())
    }
}
