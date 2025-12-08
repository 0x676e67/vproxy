use tokio::net::TcpStream;

/// A bidirectional copy between two `TcpStream`s, using zero-copy on Linux if available.
/// This function falls back to the standard `tokio::io::copy_bidirectional` on non-Linux platforms.
#[inline(always)]
pub async fn copy_bidirectional(
    a: &mut TcpStream,
    b: &mut TcpStream,
) -> std::io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        realm_io::bidi_zero_copy(a, b).await
    }

    #[cfg(not(target_os = "linux"))]
    tokio::io::copy_bidirectional(a, b).await
}
