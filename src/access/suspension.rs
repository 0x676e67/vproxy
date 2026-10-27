//! Exclusive, process-local source publication ownership. This token proves
//! which compiled Reader was withheld, not that a database/witness is current.
//! Management must retain it across uncertain outcomes and validate the exact
//! original source operation before choosing restore or a newer publication.

use super::*;

/// Owns the original compiled policy without cloning its verifiers or counters.
/// Its absence from Reader rejects new operations while old leases keep working.
/// No Drop path restores access, and fail_closed permanently invalidates it.
pub(crate) struct Suspension {
    reader: Reader,
    ticket: Arc<()>,
    policy: Option<Policy>,
}

impl Reader {
    /// Withhold the current policy under its existing short publication lock.
    /// Requires a currently available Reader and no outstanding suspension.
    /// No lock spans SQL, network work or an await. Allocation is cold, once per
    /// suspended publication; ordinary authentication keeps its existing path.
    pub(crate) fn suspend(&self) -> io::Result<Suspension> {
        let mut state = self.state.write().map_err(|_| unavailable())?;
        if state.suspension.is_some() || state.policy.is_none() {
            return Err(unavailable());
        }
        let ticket = Arc::new(());
        let policy = state.policy.take();
        state.suspension = Some(ticket.clone());
        drop(state);
        Ok(Suspension {
            reader: self.clone(),
            ticket,
            policy,
        })
    }
}

impl Suspension {
    fn valid(&self, state: &State) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| policy.revision == state.revision)
            && state.policy.is_none()
            && state
                .suspension
                .as_ref()
                .is_some_and(|ticket| Arc::ptr_eq(ticket, &self.ticket))
    }

    /// Verify this owns the caller's expected original revision, not merely
    /// whichever policy another publisher left available before suspension.
    /// This is local ownership only, not source freshness or policy impact.
    pub(crate) fn ensure(&self, revision: u64) -> io::Result<()> {
        let state = self.reader.state.read().map_err(|_| unavailable())?;
        if self.valid(&state) && state.revision == revision {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    /// Restore only this original compiled policy and its unchanged revision.
    /// The source owner must first establish a definitive non-policy outcome:
    /// exact confirmation of the original write with no proxy-policy changes,
    /// or a proven pre-dispatch rollback. A revision number alone is not that
    /// proof. Never use this after a policy mutation or an unresolved outcome.
    /// Lost/replaced ownership, fail_closed and repeated completion refuse.
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        let mut state = self.reader.state.write().map_err(|_| unavailable())?;
        if !self.valid(&state) {
            return Err(unavailable());
        }
        state.policy = self.policy.take();
        state.suspension = None;
        Ok(())
    }

    /// Publish a validated, strictly newer policy only for this suspended owner.
    /// The caller must already have exact source confirmation; this is not a
    /// witness check. Validation failure preserves the withheld original for
    /// explicit reconciliation, without making it available. No same-revision
    /// replacement or automatic rollback is allowed. Counters/traffic owners
    /// follow the same binding path as an ordinary newer publication.
    pub(crate) fn publish(&mut self, data: PolicyData) -> io::Result<()> {
        let mut policy = compile(data)?;
        let mut state = self.reader.state.write().map_err(|_| unavailable())?;
        if !self.valid(&state) {
            return Err(unavailable());
        }
        self.reader.bind_publication(&mut state, &mut policy)?;
        state.revision = policy.revision;
        let previous = state.policy.replace(policy);
        state.suspension = None;
        drop(state);
        drop(previous);
        drop(self.policy.take());
        Ok(())
    }
}

impl Drop for Suspension {
    fn drop(&mut self) {
        if let Ok(mut state) = self.reader.state.write()
            && state
                .suspension
                .as_ref()
                .is_some_and(|ticket| Arc::ptr_eq(ticket, &self.ticket))
        {
            state.suspension = None;
        }
        // Dropping the original here leaves Reader unavailable. In particular,
        // cancellation, unwind or a later permanent fence never reopens access.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::tests::{LOGIN, policy, secret};

    fn attempt(reader: &Reader) -> Result<Authorization, Error> {
        reader.authenticate(LOGIN, &secret(), Protocol::Http)
    }

    #[test]
    fn suspension_withholds_all_admission_and_restores_the_exact_old_counters() -> io::Result<()> {
        let reader = Reader::new(policy(1, 1))?;
        let flow = attempt(&reader).map_err(|_| unavailable())?;
        let mut held = reader.suspend()?;
        for protocol in [Protocol::Http, Protocol::Socks5, Protocol::Masque] {
            assert!(matches!(
                reader.authenticate(LOGIN, &secret(), protocol),
                Err(Error::Unavailable)
            ));
        }
        assert!(reader.revision().is_err());
        assert!(reader.admission().is_err());
        assert!(reader.admission_state().is_err());
        assert!(reader.suspend().is_err());
        assert!(reader.publish(policy(2, 1)).is_err());
        held.restore()?;
        assert_eq!(reader.revision()?, 1);
        assert_eq!(reader.admission()?.active_operations, 1);
        assert!(matches!(attempt(&reader), Err(Error::Capacity)));
        assert!(held.restore().is_err());
        drop(flow);
        assert!(attempt(&reader).is_ok());
        Ok(())
    }

    #[test]
    fn suspension_drop_never_restores_and_ordinary_publish_stays_strict() -> io::Result<()> {
        let reader = Reader::new(policy(1, 2))?;
        drop(reader.suspend()?);
        assert!(matches!(attempt(&reader), Err(Error::Unavailable)));
        assert!(reader.publish(policy(1, 2)).is_err());
        assert!(reader.suspend().is_err());
        reader.publish(policy(2, 2))?;
        assert_eq!(reader.revision()?, 2);
        assert!(attempt(&reader).is_ok());
        Ok(())
    }

    #[test]
    fn permanent_fence_and_another_publication_owner_invalidate_old_tokens() -> io::Result<()> {
        let reader = Reader::new(policy(1, 2))?;
        let mut old = reader.suspend()?;
        reader.fail_closed();
        assert!(old.restore().is_err());
        assert!(old.publish(policy(2, 2)).is_err());
        reader.publish(policy(2, 2))?;
        let mut current = reader.suspend()?;
        assert!(old.restore().is_err());
        assert!(old.publish(policy(3, 2)).is_err());
        drop(old); // Must not clear the new owner's distinct ticket.
        assert!(reader.publish(policy(3, 2)).is_err());
        current.restore()?;
        assert_eq!(reader.revision()?, 2);
        assert!(attempt(&reader).is_ok());
        Ok(())
    }

    #[test]
    fn suspended_publication_is_strict_and_preserves_existing_flow_counts() -> io::Result<()> {
        let reader = Reader::new(policy(1, 1))?;
        let flow = attempt(&reader).map_err(|_| unavailable())?;
        let mut held = reader.suspend()?;
        assert!(held.publish(policy(1, 1)).is_err());
        let mut invalid = policy(2, 1);
        invalid.credentials[0].secret_digest = [0; 32];
        invalid.users.clear();
        assert!(held.publish(invalid).is_err());
        assert!(matches!(attempt(&reader), Err(Error::Unavailable)));
        held.publish(policy(2, 1))?;
        assert_eq!(reader.revision()?, 2);
        assert!(held.restore().is_err());
        assert!(held.publish(policy(3, 1)).is_err());
        assert!(matches!(attempt(&reader), Err(Error::Capacity)));
        drop(flow);
        assert!(attempt(&reader).is_ok());
        Ok(())
    }
}
