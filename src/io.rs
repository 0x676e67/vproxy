use tokio::net::TcpStream;

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
