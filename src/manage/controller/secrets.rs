//! Explicit transient disclosure, separate from durable commands and receipts.

use super::*;

impl Service {
    /// Read one exact user/credential generation over the registered mTLS peer.
    /// Both local administrator/target CAS snapshots retain the real peer and
    /// network permits through their blocking worker. No store lock spans the
    /// network wait, and cancellation never retains or replays the plaintext.
    pub(in crate::manage) async fn credential_secret(
        self: &Arc<Self>,
        administrator: String,
        target_revision: u64,
        input: control::CredentialSecretRead,
    ) -> io::Result<control::CredentialSecret> {
        input.numbers()?;
        let peer = input.target_node_id.clone();
        let claim = Arc::new(self.admission.acquire(&peer).await?);
        let permit = self
            .network
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let (actor, id, retained) = (administrator.clone(), peer.clone(), claim.clone());
        let (target, permit) = self
            .policy
            .read(move |directory| {
                let _claim = retained;
                Ok((
                    targets::scoped_target(directory, &actor, &id, target_revision)?,
                    permit,
                ))
            })
            .await?;
        let reply = control::request(
            &self.policy,
            self.tls.clone(),
            &target.origin,
            &peer,
            Request::CredentialSecret(input),
        )
        .await;
        // Keep the reply owned by this worker until the final authorization
        // succeeds. An error or a cancelled receiver drops its zeroizing value.
        let reply = self
            .policy
            .read(move |directory| {
                let (_claim, _permit) = (claim, permit);
                targets::scoped_target(directory, &administrator, &peer, target_revision)?;
                reply
            })
            .await?;
        match reply {
            Reply::CredentialSecret(value) => Ok(value),
            _ => Err(invalid()),
        }
    }
}
