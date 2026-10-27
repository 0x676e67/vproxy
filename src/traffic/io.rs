use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Meter;

/// Borrow an existing stream and count its successful writes only. Reading,
/// flush and shutdown never add bytes, and no file descriptor is duplicated.
///
/// A writer facing the destination uses Upload; one facing the client uses
/// Download. Transport handshake/framing must not pass through this wrapper.
pub(crate) struct Io<'a, T> {
    inner: &'a mut T,
    meter: Option<Meter>,
}

impl<'a, T> Io<'a, T> {
    pub(crate) fn new(inner: &'a mut T, meter: Option<Meter>) -> Self {
        Self { inner, meter }
    }

    fn record(&self, result: &Poll<io::Result<usize>>) {
        if let (Some(meter), Poll::Ready(Ok(length))) = (&self.meter, result) {
            meter.add(*length);
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Io<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Io<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, buffer);
        this.record(&result);
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write_vectored(cx, buffers);
        this.record(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(target_os = "linux")]
impl<T: std::os::fd::AsRawFd> std::os::fd::AsRawFd for Io<'_, T> {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl<T: realm_io::AsyncRawIO> realm_io::AsyncRawIO for Io<'_, T> {
    fn x_poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.x_poll_read_ready(cx)
    }

    fn x_poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.x_poll_write_ready(cx)
    }

    fn x_try_io<R>(
        &self,
        interest: tokio::io::Interest,
        operation: impl FnOnce() -> io::Result<R>,
    ) -> io::Result<R> {
        // The raw write wrapper below counts the result; counting here as well
        // would count one successful pipe-to-socket splice twice.
        self.inner.x_try_io(interest, operation)
    }

    fn poll_write_raw<S>(&self, cx: &mut Context<'_>, syscall: S) -> Poll<io::Result<usize>>
    where
        S: FnMut() -> isize,
    {
        // Delegate realm_io's readiness/WouldBlock handling unchanged. This
        // public safe hook preserves real splice, not an AsyncRead copy fallback.
        let result = self.inner.poll_write_raw(cx, syscall);
        self.record(&result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::{Counter, Direction, Snapshot};
    use std::{collections::VecDeque, sync::Arc, task::Waker};

    enum Step<T> {
        Accepted(T),
        Pending,
        Failed(io::ErrorKind),
    }

    fn next<T>(steps: &mut VecDeque<Step<T>>, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        match steps.pop_front().expect("scripted I/O step") {
            Step::Accepted(value) => Poll::Ready(Ok(value)),
            Step::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Step::Failed(kind) => Poll::Ready(Err(kind.into())),
        }
    }

    /// Reports only a scripted prefix, so a counter based on buffer length or
    /// on a completed copy future cannot accidentally satisfy these tests.
    struct Script {
        writes: VecDeque<Step<usize>>,
        flushes: VecDeque<Step<()>>,
        shutdowns: VecDeque<Step<()>>,
        accepted: Vec<u8>,
        input: &'static [u8],
        vectored: bool,
        vectored_calls: usize,
    }
    impl Script {
        fn new(writes: impl IntoIterator<Item = Step<usize>>) -> Self {
            Self {
                writes: writes.into_iter().collect(),
                flushes: VecDeque::new(),
                shutdowns: VecDeque::new(),
                accepted: Vec::new(),
                input: b"read-only bytes",
                vectored: true,
                vectored_calls: 0,
            }
        }
    }
    impl AsyncRead for Script {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let length = buffer.remaining().min(this.input.len());
            buffer.put_slice(&this.input[..length]);
            this.input = &this.input[length..];
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Script {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let result = next(&mut this.writes, cx);
            if let Poll::Ready(Ok(length)) = result {
                this.accepted.extend_from_slice(&bytes[..length]);
            }
            result
        }
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.vectored_calls += 1;
            let result = next(&mut this.writes, cx);
            if let Poll::Ready(Ok(length)) = result {
                assert!(length <= buffers.iter().map(|value| value.len()).sum::<usize>());
                this.accepted.extend(
                    buffers
                        .iter()
                        .flat_map(|value| value.iter().copied())
                        .take(length),
                );
            }
            result
        }
        fn is_write_vectored(&self) -> bool {
            self.vectored
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            next(&mut self.get_mut().flushes, cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            next(&mut self.get_mut().shutdowns, cx)
        }
    }

    fn counter() -> Arc<Counter> {
        Arc::new(Counter::new(Snapshot {
            upload: 0,
            download: 0,
            saturated: false,
        }))
    }

    #[test]
    fn partial_write_survives_pending_error_and_wrapper_drop() {
        let counter = counter();
        let mut script = Script::new([
            Step::Accepted(3),
            Step::Pending,
            Step::Failed(io::ErrorKind::BrokenPipe),
        ]);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut stream = Io::new(
                &mut script,
                Some(Meter::new(counter.clone(), Direction::Upload)),
            );
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"abcdef"),
                Poll::Ready(Ok(3))
            ));
            assert_eq!(counter.snapshot().upload, 3);
            assert!(
                Pin::new(&mut stream)
                    .poll_write(&mut cx, b"def")
                    .is_pending()
            );
            assert_eq!(counter.snapshot().upload, 3);
            assert!(
                matches!(Pin::new(&mut stream).poll_write(&mut cx, b"def"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
        }
        assert_eq!(script.accepted, b"abc");
        assert_eq!(
            counter.snapshot(),
            Snapshot {
                upload: 3,
                download: 0,
                saturated: false
            }
        );
    }

    #[test]
    fn read_flush_shutdown_and_zero_write_do_not_add_payload() {
        let counter = counter();
        let mut script = Script::new([Step::Accepted(2), Step::Accepted(0)]);
        script.vectored = false;
        script.flushes = [
            Step::Pending,
            Step::Failed(io::ErrorKind::WriteZero),
            Step::Accepted(()),
        ]
        .into();
        script.shutdowns = [
            Step::Pending,
            Step::Failed(io::ErrorKind::ConnectionReset),
            Step::Accepted(()),
        ]
        .into();
        let mut cx = Context::from_waker(Waker::noop());
        let mut stream = Io::new(
            &mut script,
            Some(Meter::new(counter.clone(), Direction::Download)),
        );
        assert!(!stream.is_write_vectored());
        let mut bytes = [0; 32];
        let mut buffer = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buffer),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buffer.filled(), b"read-only bytes");
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"abc"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"c"),
            Poll::Ready(Ok(0))
        ));
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        assert!(
            matches!(Pin::new(&mut stream).poll_flush(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero)
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        assert!(
            matches!(Pin::new(&mut stream).poll_shutdown(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            counter.snapshot(),
            Snapshot {
                upload: 0,
                download: 2,
                saturated: false
            }
        );
    }

    #[test]
    fn vectored_write_counts_only_the_accepted_cross_slice_prefix() {
        let counter = counter();
        let mut script = Script::new([
            Step::Accepted(5),
            Step::Pending,
            Step::Failed(io::ErrorKind::BrokenPipe),
        ]);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut stream = Io::new(
                &mut script,
                Some(Meter::new(counter.clone(), Direction::Download)),
            );
            assert!(stream.is_write_vectored());
            let buffers = [
                IoSlice::new(b"ab"),
                IoSlice::new(b"cdef"),
                IoSlice::new(b"ghi"),
            ];
            assert!(matches!(
                Pin::new(&mut stream).poll_write_vectored(&mut cx, &buffers),
                Poll::Ready(Ok(5))
            ));
            assert!(
                Pin::new(&mut stream)
                    .poll_write_vectored(&mut cx, &buffers)
                    .is_pending()
            );
            assert!(
                matches!(Pin::new(&mut stream).poll_write_vectored(&mut cx, &buffers), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
        }
        assert_eq!(script.vectored_calls, 3);
        assert_eq!(script.accepted, b"abcde");
        assert_eq!(
            counter.snapshot(),
            Snapshot {
                upload: 0,
                download: 5,
                saturated: false
            }
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use realm_io::AsyncRawIO;
        use std::{
            os::fd::{AsRawFd, RawFd},
            sync::atomic::{AtomicU64, AtomicUsize, Ordering},
            time::Duration,
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt, Interest},
            net::{TcpListener, TcpStream},
            task::JoinSet,
            time::timeout,
        };

        #[derive(Default)]
        struct Trace {
            user_calls: AtomicUsize,
            raw_writes: AtomicUsize,
            raw_bytes: AtomicU64,
        }
        struct RawStream {
            inner: TcpStream,
            trace: Arc<Trace>,
        }
        impl AsRawFd for RawStream {
            fn as_raw_fd(&self) -> RawFd {
                self.inner.as_raw_fd()
            }
        }
        impl AsyncRead for RawStream {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                this.trace.user_calls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut this.inner).poll_read(cx, buffer)
            }
        }
        impl AsyncWrite for RawStream {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                this.trace.user_calls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut this.inner).poll_write(cx, buffer)
            }
            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buffers: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                this.trace.user_calls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut this.inner).poll_write_vectored(cx, buffers)
            }
            fn is_write_vectored(&self) -> bool {
                self.inner.is_write_vectored()
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }
        impl AsyncRawIO for RawStream {
            fn x_poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.inner.x_poll_read_ready(cx)
            }
            fn x_poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.inner.x_poll_write_ready(cx)
            }
            fn x_try_io<R>(
                &self,
                interest: Interest,
                operation: impl FnOnce() -> io::Result<R>,
            ) -> io::Result<R> {
                self.inner.x_try_io(interest, operation)
            }
            fn poll_write_raw<S>(&self, cx: &mut Context<'_>, syscall: S) -> Poll<io::Result<usize>>
            where
                S: FnMut() -> isize,
            {
                let result = self.inner.poll_write_raw(cx, syscall);
                if let Poll::Ready(Ok(length)) = result
                    && length != 0
                {
                    self.trace.raw_writes.fetch_add(1, Ordering::Relaxed);
                    self.trace
                        .raw_bytes
                        .fetch_add(u64::try_from(length).unwrap(), Ordering::Relaxed);
                }
                result
            }
        }

        async fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, server) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            (client.unwrap(), server.unwrap().0)
        }

        struct Bridge {
            client: TcpStream,
            target: TcpStream,
            counter: Arc<Counter>,
            down: Arc<Trace>,
            up: Arc<Trace>,
            worker: tokio::task::AbortHandle,
        }

        async fn bridge(tasks: &mut JoinSet<io::Result<(u64, u64)>>) -> Bridge {
            let (client, left) = pair().await;
            let (right, target) = pair().await;
            let counter = counter();
            let (left_trace, right_trace) =
                (Arc::new(Trace::default()), Arc::new(Trace::default()));
            let (down, up) = (left_trace.clone(), right_trace.clone());
            let shared = counter.clone();
            let worker = tasks.spawn(async move {
                let mut left = RawStream {
                    inner: left,
                    trace: down,
                };
                let mut right = RawStream {
                    inner: right,
                    trace: up,
                };
                let mut left = Io::new(
                    &mut left,
                    Some(Meter::new(shared.clone(), Direction::Download)),
                );
                let mut right = Io::new(&mut right, Some(Meter::new(shared, Direction::Upload)));
                crate::server::io::copy_bidirectional(&mut left, &mut right).await
            });
            Bridge {
                client,
                target,
                counter,
                down: left_trace,
                up: right_trace,
                worker,
            }
        }

        fn assert_raw_only(counter: &Counter, down: &Trace, up: &Trace) {
            assert_eq!(down.user_calls.load(Ordering::Relaxed), 0);
            assert_eq!(up.user_calls.load(Ordering::Relaxed), 0);
            assert!(up.raw_writes.load(Ordering::Relaxed) > 0);
            assert_eq!(
                counter.snapshot().upload,
                up.raw_bytes.load(Ordering::Relaxed)
            );
            assert_eq!(
                counter.snapshot().download,
                down.raw_bytes.load(Ordering::Relaxed)
            );
        }

        #[tokio::test]
        async fn real_splice_counts_both_directions_once_and_preserves_half_close() {
            let mut tasks = JoinSet::new();
            timeout(Duration::from_secs(10), async {
                let Bridge {
                    mut client,
                    mut target,
                    counter,
                    down,
                    up,
                    ..
                } = bridge(&mut tasks).await;
                let send = async move {
                    client.write_all(&vec![0x41; 64 * 1024]).await.unwrap();
                    client.shutdown().await.unwrap();
                    let mut bytes = Vec::new();
                    client.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, vec![0x42; 4096]);
                };
                let receive = async move {
                    let mut bytes = Vec::new();
                    target.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(bytes, vec![0x41; 64 * 1024]);
                    target.write_all(&vec![0x42; 4096]).await.unwrap();
                    target.shutdown().await.unwrap();
                };
                tokio::join!(send, receive);
                assert_eq!(
                    tasks.join_next().await.unwrap().unwrap().unwrap(),
                    (64 * 1024, 4096)
                );
                assert_eq!(
                    counter.snapshot(),
                    Snapshot {
                        upload: 64 * 1024,
                        download: 4096,
                        saturated: false
                    }
                );
                assert!(down.raw_writes.load(Ordering::Relaxed) > 0);
                assert_raw_only(&counter, &down, &up);
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn cancelling_real_splice_retains_previously_accepted_payload() {
            // Both JoinSets abort their owned tasks if an assertion or deadline
            // fails. No detached sender or proxy survives a failed fixture.
            let (mut tasks, mut senders) = (JoinSet::new(), JoinSet::new());
            timeout(Duration::from_secs(10), async {
                let Bridge {
                    mut client,
                    mut target,
                    counter,
                    down,
                    up,
                    worker,
                } = bridge(&mut tasks).await;
                senders.spawn(async move {
                    let bytes = vec![0x43; 64 * 1024];
                    while client.write_all(&bytes).await.is_ok() {}
                });
                let mut prefix = vec![0; 64 * 1024];
                target.read_exact(&mut prefix).await.unwrap();
                assert!(prefix.iter().all(|byte| *byte == 0x43));
                let before = counter.snapshot();
                assert!(before.upload >= 64 * 1024);
                worker.abort();
                assert!(tasks.join_next().await.unwrap().unwrap_err().is_cancelled());
                let after = counter.snapshot();
                assert!(after.upload >= before.upload);
                senders.shutdown().await;
                let mut received = 64 * 1024u64;
                let mut bytes = [0; 8192];
                loop {
                    match target.read(&mut bytes).await {
                        Ok(0) | Err(_) => break,
                        Ok(length) => {
                            assert!(bytes[..length].iter().all(|byte| *byte == 0x43));
                            received = received
                                .checked_add(u64::try_from(length).unwrap())
                                .unwrap();
                        }
                    }
                }
                // Accepted-by-transport is not acknowledgement by the peer.
                assert!(received <= after.upload);
                assert_eq!(counter.snapshot(), after);
                assert_raw_only(&counter, &down, &up);
            })
            .await
            .unwrap();
        }
    }
}
