//! Lightweight witness vocabulary. A record is an independently retained
//! high-water mark, not a recoverable log, lease or proof of infrastructure
//! fencing. Source transaction integration is deliberately not enabled yet.

use super::store;
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};

mod client;

/// Enrollment/retirement belong to the offline witness operator. Remote
/// operations use the bound source identity, never proxy-owner authority.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Contact an enrolled witness from an offline source directory
    Remote(client::Args),
    /// Bind one already enrolled peer to an immutable writer and baseline
    Bind {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// JSON Enrollment containing only IDs and an opaque state commitment
        #[arg(long)]
        input: PathBuf,
    },
    /// Read a retained record, including a permanent retirement tombstone
    Inspect {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        binding_id: String,
    },
    /// Permanently stop this binding at an exact observed high-water mark
    Retire {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        binding_id: String,
        #[arg(long)]
        expected_sequence: String,
        #[arg(long)]
        expected_commitment: String,
    },
}

/// Immutable enrollment chosen by the offline witness operator. Replacing a
/// missing witness with a new binding cannot satisfy the old binding ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    /// Exact witness identity; prevents applying a request to a different node.
    pub(super) witness_node_id: String,
    /// Caller-retained random 128-bit binding ID; never inferred from a peer.
    pub(super) binding_id: String,
    /// Already registered peer; no proxy-owner permission is implied or needed.
    pub(super) peer_node_id: String,
    /// One source incarnation, independent of its stable TLS/node identity.
    pub(super) writer_id: String,
    /// Lowercase SHA-256 commitment to the initial protected state. The witness
    /// cannot independently validate source bytes; enrollment is not freshness.
    pub(super) baseline: String,
}

/// Pending is durable *before* the source may commit. A failed source commit
/// leaves it pending: there is no abort, decrement or rollback-to-backup action.
/// Confirmed is the bound writer's acknowledgement, not independent evidence
/// that source integration or same-ID activation has been implemented.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Pending,
    Confirmed,
}

/// Only the current transition is retained. Its operation identity is the
/// immutable (binding, writer, sequence) tuple, so expired operations cannot be
/// assigned a fresh payload or accidentally consume another sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    /// Original enrollment stays intact as the current transition advances.
    pub(super) enrollment: Enrollment,
    /// Canonical decimal through i64::MAX, preserving exact browser integers.
    pub(super) sequence: String,
    /// Previous commitment of the current transition; absent only at baseline.
    pub(super) previous: Option<String>,
    /// Proposed state in Pending; writer-acknowledged state in Confirmed.
    pub(super) commitment: String,
    pub(super) phase: Phase,
    /// Permanent even for exact retries. Retiring never deletes the high water.
    pub(super) retired: bool,
}

/// Identical payload for reserve, confirm and lost-reply reconciliation. This
/// contains no credential, SQL, command body or recoverable user data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transition {
    /// Exact node hosting the independently retained witness database.
    pub(super) witness_node_id: String,
    /// Immutable enrollment, never a peer name or an automatically renewed ID.
    pub(super) binding_id: String,
    /// Exact incarnation from enrollment, not the caller's current process ID.
    pub(super) writer_id: String,
    /// Positive canonical decimal; together with binding/writer this is the ID.
    pub(super) sequence: String,
    /// State the caller expects to supersede, checked in the write transaction.
    pub(super) previous: String,
    /// Opaque SHA-256 of the proposed protected state, not recoverable content.
    pub(super) commitment: String,
}

/// Stable non-secret domain failures; SQLite/I/O errors are never converted to
/// these rejections or treated as evidence that an uncertain commit rolled back.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum Error {
    #[error("witness_invalid")]
    Invalid,
    #[error("witness_conflict")]
    Conflict,
    #[error("witness_denied")]
    Denied,
    #[error("witness_upgrade_required")]
    UpgradeRequired,
    #[error("witness_capacity")]
    Capacity,
}
impl Error {
    pub(super) fn error(self) -> io::Error {
        io::Error::new(
            match self {
                Self::Invalid => io::ErrorKind::InvalidInput,
                Self::Denied => io::ErrorKind::PermissionDenied,
                Self::UpgradeRequired => io::ErrorKind::Unsupported,
                Self::Conflict | Self::Capacity => io::ErrorKind::AlreadyExists,
            },
            self,
        )
    }
}

/// Canonical non-negative SQL-sized revision; alternate spellings such as +1
/// and 01 cannot split one operation into two IDs.
pub(super) fn sequence(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= i64::MAX as u64 && n.to_string() == value)
        .ok_or_else(|| Error::Invalid.error())
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Enrollment {
    pub(super) fn validate(&self) -> io::Result<()> {
        if ![
            &self.witness_node_id,
            &self.binding_id,
            &self.peer_node_id,
            &self.writer_id,
        ]
        .into_iter()
        .all(|id| store::valid_id(id))
            || self.witness_node_id == self.peer_node_id
            || !digest(&self.baseline)
        {
            return Err(Error::Invalid.error());
        }
        Ok(())
    }
}
impl Record {
    /// Check the baseline/transition shape independently of storage or TLS.
    /// A valid record still needs its expected enrollment and operation checked;
    /// it does not prove that the source committed or that a backup is fresh.
    pub(super) fn validate(&self) -> io::Result<()> {
        self.enrollment.validate()?;
        let n = sequence(&self.sequence)?;
        if !digest(&self.commitment)
            || (n == 0
                && (self.previous.is_some()
                    || self.phase != Phase::Confirmed
                    || self.commitment != self.enrollment.baseline))
            || (n != 0 && !self.previous.as_ref().is_some_and(|v| digest(v)))
        {
            return Err(Error::Invalid.error());
        }
        Ok(())
    }
}
impl Transition {
    pub(super) fn validate(&self) -> io::Result<()> {
        if ![&self.witness_node_id, &self.binding_id, &self.writer_id]
            .into_iter()
            .all(|id| store::valid_id(id))
            || sequence(&self.sequence)? == 0
            || !digest(&self.previous)
            || !digest(&self.commitment)
        {
            return Err(Error::Invalid.error());
        }
        Ok(())
    }
}

/// Read bounded public metadata and print only a validated non-secret record.
/// Local mutations hold offline locks; remote operations take the source's
/// process-author lock and use explicit node mTLS files, without starting serve.
pub(super) fn run(command: Command) -> io::Result<()> {
    let record = match command {
        Command::Remote(args) => client::run(args)?,
        Command::Bind { data_dir, input } => {
            let bytes = super::files::read(&input, 4096, false)?;
            let enrollment = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid.error())?;
            store::witness::bind(&super::directory(data_dir)?, &enrollment)?
        }
        Command::Inspect {
            data_dir,
            binding_id,
        } => store::witness::inspect(&super::directory(data_dir)?, &binding_id)?,
        Command::Retire {
            data_dir,
            binding_id,
            expected_sequence,
            expected_commitment,
        } => store::witness::retire(
            &super::directory(data_dir)?,
            &binding_id,
            &expected_sequence,
            &expected_commitment,
        )?,
    };
    serde_json::to_writer(io::stdout().lock(), &record)
        .map_err(|_| io::Error::other("cannot write witness record"))
}
