//! [`Accept`] trait and utilities.

use std::{
    future::{Future, Ready},
    io,
};

/// An asynchronous function to modify io stream and service.
pub trait Accept<I> {
    /// IO stream produced by accept.
    type Stream;

    /// Future return value.
    type Future: Future<Output = io::Result<Self::Stream>>;

    /// Process io stream and service asynchronously.
    fn accept(&self, stream: I) -> Self::Future;
}

/// A no-op acceptor.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultAcceptor;

impl DefaultAcceptor {
    /// Create a new default acceptor.
    pub fn new() -> Self {
        Self
    }
}

impl<I> Accept<I> for DefaultAcceptor {
    type Stream = I;
    type Future = Ready<io::Result<Self::Stream>>;

    fn accept(&self, stream: I) -> Self::Future {
        std::future::ready(Ok(stream))
    }
}
