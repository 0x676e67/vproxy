use realm_io::AsyncRawIO;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + AsyncRawIO + Unpin,
    B: AsyncRead + AsyncWrite + AsyncRawIO + Unpin,
{
    #[cfg(target_os = "linux")]
    {
        realm_io::bidi_zero_copy(a, b).await
    }

    #[cfg(not(target_os = "linux"))]
    tokio::io::copy_bidirectional(a, b).await
}
