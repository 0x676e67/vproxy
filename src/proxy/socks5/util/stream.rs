use std::time::Duration;

use tokio::{
    io::ErrorKind as IOErrorKind,
    net::{TcpStream, ToSocketAddrs},
    time::timeout,
};

use crate::proxy::socks5::{ReplyError, Result};

#[macro_export]
macro_rules! read_exact {
    ($stream:expr, $array:expr) => {{
        let mut x = $array;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub async fn tcp_connect_with_timeout<T>(addr: T, request_timeout_s: u64) -> Result<TcpStream>
where
    T: ToSocketAddrs,
{
    let fut = tcp_connect(addr);
    match timeout(Duration::from_secs(request_timeout_s), fut).await {
        Ok(result) => result,
        Err(_) => Err(ReplyError::ConnectionTimeout.into()),
    }
}

pub async fn tcp_connect<T>(addr: T) -> Result<TcpStream>
where
    T: ToSocketAddrs,
{
    match TcpStream::connect(addr).await {
        Ok(o) => Ok(o),
        Err(e) => match e.kind() {
            IOErrorKind::ConnectionRefused => Err(ReplyError::ConnectionRefused.into()),
            IOErrorKind::ConnectionAborted => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::ConnectionReset => Err(ReplyError::ConnectionNotAllowed.into()),
            IOErrorKind::NotConnected => Err(ReplyError::NetworkUnreachable.into()),
            _ => Err(e.into()), 
        },
    }
}
