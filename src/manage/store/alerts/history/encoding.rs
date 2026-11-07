//! Preserve the original canonical batch bytes without allocating a second
//! complete JSON image. This bounds digest output buffering, not retained
//! observations held by the collector.

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
