use std::io;

use bytes::Buf;

use super::Meter;

/// Zero-copy DATA view whose consumption corresponds to a successful transport
/// write only in the explicitly configured H1 Queue/H3 Quinn send paths.
///
/// Never use it to count `poll_frame`, a pre-encoding copy, H2 ordinary DATA or
/// h3-quinn's generic datagram writer: those can consume before a successful send.
pub(crate) struct Data<B> {
    inner: B,
    prefix: usize,
    meter: Option<Meter>,
}

impl<B> Data<B> {
    /// All bytes are payload. Keeping the meter with queued DATA preserves a
    /// successful prefix even if its body owner is dropped before the queue.
    pub(crate) fn new(inner: B, meter: Option<Meter>) -> Self {
        Self {
            inner,
            prefix: 0,
            meter,
        }
    }
}

impl<B: Buf> Data<B> {
    /// Exclude a leading Capsule type/length/context prefix from this DATA frame.
    /// A prefix outside the encoded buffer is an internal input error, not a
    /// peer protocol error. H3 frame headers are excluded by H3's WriteBuf itself.
    pub(crate) fn prefixed(inner: B, prefix: usize, meter: Option<Meter>) -> io::Result<Self> {
        if prefix > inner.remaining() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "traffic prefix exceeds DATA",
            ));
        }
        Ok(Self {
            inner,
            prefix,
            meter,
        })
    }
}

impl<B: Buf> Buf for Data<B> {
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.inner.chunk()
    }

    fn chunks_vectored<'a>(&'a self, slices: &mut [io::IoSlice<'a>]) -> usize {
        self.inner.chunks_vectored(slices)
    }

    fn advance(&mut self, count: usize) {
        // Preserve Buf's count<=remaining precondition. Do not record anything
        // until the inner buffer has accepted the advance.
        self.inner.advance(count);
        let metadata = self.prefix.min(count);
        self.prefix -= metadata;
        if let Some(meter) = &self.meter {
            meter.add(count - metadata);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::traffic::{Direction, Meter, tests::counter};

    #[test]
    fn payload_prefix_is_excluded_across_fragmented_advances_and_drop() {
        let count = counter();
        let meter = Meter::new(count.clone(), Direction::Download);
        let mut data = Data::prefixed(Bytes::from_static(b"HEADpayload"), 4, Some(meter)).unwrap();
        data.advance(2);
        assert_eq!(count.snapshot().download, 0);
        data.advance(4);
        assert_eq!(data.chunk(), b"yload");
        assert_eq!(count.snapshot().download, 2);
        drop(data); // The five unaccepted bytes must not be added on cancellation.
        assert_eq!(count.snapshot().download, 2);
        assert!(Data::prefixed(Bytes::new(), 1, None).is_err());
    }

    #[test]
    fn chained_chunks_are_not_merged_or_counted_by_observation() {
        let count = counter();
        let inner = Bytes::from_static(b"abc").chain(Bytes::from_static(b"def"));
        let mut data = Data::new(inner, Some(Meter::new(count.clone(), Direction::Upload)));
        let mut chunks = [io::IoSlice::new(&[]); 2];
        assert_eq!(data.remaining(), 6);
        assert_eq!(data.chunks_vectored(&mut chunks), 2);
        assert_eq!(&*chunks[0], b"abc");
        assert_eq!(&*chunks[1], b"def");
        assert_eq!(count.snapshot().upload, 0);
        data.advance(4);
        assert_eq!(data.chunk(), b"ef");
        assert_eq!(count.snapshot().upload, 4);
    }
}
