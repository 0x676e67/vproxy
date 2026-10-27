use tokio::io::{AsyncRead, AsyncWrite};

/// Copy between raw-socket transports without bypassing their write observers.
///
/// Linux keeps realm_io's socket/pipe splice path, including for a borrowed
/// traffic wrapper. Both streams must expose their actual descriptor; this is
/// not suitable for a TLS or other transport with userspace framing.
#[cfg(target_os = "linux")]
#[inline(always)]
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + realm_io::AsyncRawIO + Unpin,
    B: AsyncRead + AsyncWrite + realm_io::AsyncRawIO + Unpin,
{
    realm_io::bidi_zero_copy(a, b).await
}

/// Copy through the normal asynchronous read/write interface on other platforms.
/// Partial writes are visible to a transport's observer before a later failure
/// or cancellation; the returned totals are available only on full completion.
#[cfg(not(target_os = "linux"))]
#[inline(always)]
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}
