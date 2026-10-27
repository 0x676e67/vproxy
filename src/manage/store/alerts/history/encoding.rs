//! Preserve the original canonical batch bytes without allocating a second
//! complete JSON image. This bounds digest output buffering, not retained
//! observations, SQLite Session memory or the eventual Source changeset.

use super::{Batch, Error};
use sha2::{Digest, Sha256};
use std::io::{self, BufWriter, Write};

const BUFFER_BYTES: usize = 8 * 1024;

/// Counts actual UTF-8 bytes before accepting them into the digest. Capacity
/// failure is sticky, including a BufWriter drop attempting another flush.
struct DigestWriter {
    hash: Sha256,
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl DigestWriter {
    fn new(limit: usize) -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            limit,
            exceeded: false,
        }
    }
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| !self.exceeded && *n <= self.limit)
        else {
            self.exceeded = true;
            return Err(io::Error::other("alert batch digest capacity exceeded"));
        };
        self.bytes = next;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Called after the existing per-transition validation. The same serde JSON
/// representation remains the receipt identity; buffering avoids hashing every
/// one-byte punctuation write separately. Only a successful final flush may
/// return a digest, including for a body smaller than the 8KiB buffer.
pub(super) fn batch_digest(batch: &Batch, limit: usize) -> io::Result<[u8; 32]> {
    let mut output = DigestWriter::new(limit);
    let result = {
        let mut buffered = BufWriter::with_capacity(BUFFER_BYTES, &mut output);
        serde_json::to_writer(&mut buffered, batch)
            .map_err(|_| ())
            .and_then(|()| buffered.flush().map_err(|_| ()))
    };
    if output.exceeded {
        return Err(Error::Capacity.error());
    }
    result.map_err(|()| Error::Invalid.error())?;
    Ok(output.hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::super::{
        EndReason, MAX_BATCH, MAX_PAYLOAD, Observation, Transition, TransitionKind, encode,
        validate_observation,
    };
    use super::*;
    use crate::manage::{alerts::Kind, health::CheckKind};

    fn batch(count: usize) -> Batch {
        Batch {
            boot_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            sequence: i64::MAX as u64,
            transitions: (0..count)
                .map(|n| Transition {
                    kind: TransitionKind::Unmonitored,
                    observation: Observation {
                        incident_id: u64::MAX - n as u64,
                        kind: Kind::EgressCheck,
                        origin_node_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                        resource_id: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
                        slot: format!("source:AAAAAAAAAAAAAAAAAAAAAA:{}", u64::MAX - n as u64),
                        check: Some(CheckKind::Tcp),
                        target: Some(std::net::SocketAddr::from((
                            std::net::Ipv6Addr::new(
                                0x2001, 0x4860, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                            ),
                            u16::MAX,
                        ))),
                        code: "egress_network_unreachable".into(),
                        first_observed_at_unix_ms: Some(u64::MAX),
                        last_observed_at_unix_ms: Some(u64::MAX),
                        evidence_sequence: Some(u64::MAX),
                    },
                    observed_at_unix_ms: Some(u64::MAX),
                    ended_reason: Some(EndReason::SourceUnmonitored),
                })
                .collect(),
        }
    }

    /// Exact pre-change digest algorithm, kept only as an independent byte
    /// compatibility/reference implementation for this performance change.
    fn legacy_digest(batch: &Batch, limit: usize) -> io::Result<[u8; 32]> {
        if !super::super::super::super::valid_id(&batch.boot_id)
            || batch.sequence == 0
            || batch.sequence > i64::MAX as u64
            || batch.transitions.is_empty()
            || batch.transitions.len() > limit
        {
            return Err(Error::Invalid.error());
        }
        let mut total = 0usize;
        for transition in &batch.transitions {
            validate_observation(&transition.observation)?;
            if (transition.kind == TransitionKind::Unmonitored)
                != (transition.ended_reason == Some(EndReason::SourceUnmonitored))
            {
                return Err(Error::Invalid.error());
            }
            total = total
                .checked_add(encode(transition)?.len())
                .ok_or_else(|| Error::Capacity.error())?;
        }
        if total
            > limit
                .checked_mul(MAX_PAYLOAD)
                .ok_or_else(|| Error::Capacity.error())?
        {
            return Err(Error::Capacity.error());
        }
        let bytes = serde_json::to_vec(batch).map_err(|_| Error::Invalid.error())?;
        let max = limit
            .checked_mul(MAX_PAYLOAD + 1)
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| Error::Capacity.error())?;
        if bytes.len() > max {
            return Err(Error::Capacity.error());
        }
        Ok(Sha256::digest(bytes).into())
    }

    #[test]
    fn buffered_digest_matches_legacy_for_small_full_and_nullable_batches() -> io::Result<()> {
        for count in [1, 17, MAX_BATCH] {
            let mut value = batch(count);
            for (index, transition) in value.transitions.iter_mut().enumerate() {
                if index % 2 == 0 {
                    transition.observed_at_unix_ms = None;
                    transition.observation.first_observed_at_unix_ms = None;
                    transition.observation.evidence_sequence = None;
                }
            }
            assert_eq!(
                super::super::digest(&value, MAX_BATCH)?,
                legacy_digest(&value, MAX_BATCH)?
            );
            value.transitions.reverse();
            assert_eq!(
                super::super::digest(&value, MAX_BATCH)?,
                legacy_digest(&value, MAX_BATCH)?
            );
        }
        Ok(())
    }

    #[test]
    fn digest_capacity_includes_final_buffer_and_overflow_and_remains_sticky() -> io::Result<()> {
        for count in [1, 17] {
            let value = batch(count);
            let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
            assert_eq!(
                batch_digest(&value, bytes.len())?,
                <[u8; 32]>::from(Sha256::digest(&bytes))
            );
            for limit in [0, bytes.len() - 1] {
                assert_eq!(
                    batch_digest(&value, limit)
                        .err()
                        .and_then(|e| e.into_inner())
                        .and_then(|e| e.downcast::<Error>().ok())
                        .map(|e| *e),
                    Some(Error::Capacity)
                );
            }
        }
        let mut output = DigestWriter::new(usize::MAX);
        output.bytes = usize::MAX;
        assert!(output.write_all(b"x").is_err());
        output.bytes = 0;
        assert!(output.write_all(b"x").is_err());
        assert_eq!(output.bytes, 0);
        Ok(())
    }

    #[test]
    fn streaming_keeps_original_validation_and_digest_conflict_boundaries() -> io::Result<()> {
        let mut value = batch(1);
        for limit in [0, 1, MAX_BATCH, usize::MAX] {
            let original = legacy_digest(&value, limit);
            let current = super::super::digest(&value, limit);
            match (original, current) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
                _ => return Err(io::Error::other("digest compatibility differs")),
            }
        }
        let first = super::super::digest(&value, MAX_BATCH)?;
        value.transitions[0].observation.code = "egress_failed".into();
        assert_ne!(super::super::digest(&value, MAX_BATCH)?, first);
        value.transitions[0].ended_reason = None;
        assert_eq!(
            super::super::digest(&value, MAX_BATCH)
                .err()
                .map(|e| e.to_string()),
            legacy_digest(&value, MAX_BATCH)
                .err()
                .map(|e| e.to_string())
        );
        Ok(())
    }

    /// Run the same test executable in separate processes with GNU time -v;
    /// VPROXY_TEST_DIGEST_MODE selects `legacy`/`stream`. Not a service or Session
    /// benchmark: only full syntactically valid batch hashing is measured.
    #[test]
    #[ignore = "manual paired RSS diagnostic; requires VPROXY_TEST_DIGEST_MODE"]
    fn full_batch_digest_memory_diagnostic() -> io::Result<()> {
        let mode = std::env::var("VPROXY_TEST_DIGEST_MODE").map_err(io::Error::other)?;
        if !matches!(mode.as_str(), "legacy" | "stream") {
            return Err(io::Error::other("unknown digest diagnostic mode"));
        }
        let value = batch(MAX_BATCH);
        let started = std::time::Instant::now();
        let mut hash = [0u8; 32];
        for _ in 0..3 {
            hash = if mode == "legacy" {
                legacy_digest(std::hint::black_box(&value), MAX_BATCH)?
            } else {
                super::super::digest(std::hint::black_box(&value), MAX_BATCH)?
            };
            std::hint::black_box(hash);
        }
        let elapsed = started.elapsed().as_micros();
        let mut output = DigestWriter::new(usize::MAX);
        serde_json::to_writer(&mut output, &value).map_err(io::Error::other)?;
        assert_eq!(hash, <[u8; 32]>::from(output.hash.finalize()));
        println!(
            "DIGEST_DIAGNOSTIC mode={mode} transitions={} json_bytes={} elapsed_us={elapsed} sha256={hash:02x?}",
            value.transitions.len(),
            output.bytes
        );
        Ok(())
    }
}
