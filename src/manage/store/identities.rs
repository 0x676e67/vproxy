//! Trusted file-author operations in an already-held Source transaction. This
//! is not an administrator, peer or automation permission and has no HTTP route.

use super::*;

/// Borrow only the transaction accepted by the original Source file-author
/// path. This type does not establish filesystem authority by itself: the
/// Coordinator must first check the exact retained author and offline state.
pub(in crate::manage) struct Writer<'a> {
    directory: &'a Path,
    transaction: &'a rusqlite::Transaction<'a>,
}

impl<'a> Writer<'a> {
    pub(in crate::manage) fn new(
        directory: &'a Path,
        transaction: &'a rusqlite::Transaction<'a>,
    ) -> Self {
        Self {
            directory,
            transaction,
        }
    }

    /// Explicit offline grant/takeover: expected_epoch is a positive CAS and
    /// controller, if selected, must be an enrolled active peer. Even the same
    /// owner advances epoch and invalidates the old command namespace. Audit
    /// uses file authority, not an impersonated administrator; the original
    /// worker confirms before returning this non-secret ownership metadata.
    pub(in crate::manage) fn set_owner(
        &mut self,
        expected_epoch: u64,
        controller: Option<&str>,
    ) -> io::Result<Ownership> {
        control::set_owner_offline_in(self.transaction, expected_epoch, controller)
    }

    /// Enroll only under this offline file author; no network request can
    /// create a binding or overwrite an existing/retired writer's high-water.
    pub(in crate::manage) fn bind_witness(
        &mut self,
        enrollment: &crate::manage::witness::Enrollment,
    ) -> io::Result<crate::manage::witness::Record> {
        witness::bind_in(self.transaction, enrollment)
    }

    /// Permanently retire the original binding at its observed sequence/hash.
    /// Confirmation and output still belong to the accepted Source worker.
    pub(in crate::manage) fn retire_witness(
        &mut self,
        binding: &str,
        expected_sequence: &str,
        expected_commitment: &str,
    ) -> io::Result<crate::manage::witness::Record> {
        witness::retire_in(
            self.transaction,
            binding,
            expected_sequence,
            expected_commitment,
        )
    }

    /// DER must already pass the operator's CA/name verification. Source also
    /// refuses candidate changes to its own bound witness authorization.
    pub(in crate::manage) fn register_peer(
        &mut self,
        node_id: &str,
        name: &str,
        der: &[u8],
        expected_san: &str,
        expected_revision: Option<u64>,
    ) -> io::Result<PeerSummary> {
        peers::register_in(
            self.transaction,
            node_id,
            name,
            der,
            expected_san,
            expected_revision,
        )
    }

    pub(in crate::manage) fn set_peer_active(
        &mut self,
        node_id: &str,
        expected_revision: u64,
        active: bool,
    ) -> io::Result<PeerSummary> {
        peers::active_in(self.transaction, node_id, expected_revision, active)
    }

    pub(in crate::manage) fn revoke_certificate(
        &mut self,
        der: &[u8],
        expected_revision: u64,
    ) -> io::Result<PeerSummary> {
        peers::revoke_in(self.transaction, der, expected_revision)
    }

    /// The returned raw key remains owned and zeroizing. Only the outer
    /// post-confirmation continuation may deliver it; it is never replayed.
    pub(in crate::manage) fn create_automation(
        &mut self,
        name: &str,
        scope: automation::Scope,
        valid_for_seconds: u64,
    ) -> io::Result<automation::Issued> {
        automation::create_in(self.transaction, name, scope, valid_for_seconds)
    }

    pub(in crate::manage) fn rotate_automation(
        &mut self,
        id: &str,
        expected_generation: u64,
        valid_for_seconds: u64,
    ) -> io::Result<automation::Issued> {
        automation::rotate_in(self.transaction, id, expected_generation, valid_for_seconds)
    }

    pub(in crate::manage) fn revoke_automation(
        &mut self,
        id: &str,
        expected_generation: u64,
    ) -> io::Result<automation::View> {
        automation::revoke_in(self.transaction, id, expected_generation)
    }

    /// Backup uses a new private path and captures the old committed verifier.
    /// It is retained on failure and cannot be overwritten by an exact retry.
    pub(in crate::manage) fn reset_password(
        &mut self,
        administrator: &str,
        password_hash: &str,
        backup_path: &Path,
    ) -> io::Result<Overview> {
        administrators::reset_in(
            self.directory,
            self.transaction,
            administrator,
            password_hash,
            backup_path,
        )
    }
}
