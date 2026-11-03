// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP serving for a plaintext listener, with the timeouts §6.3's step 2
//! records.
//!
//! Header-read and idle are one hyper timer: 4 seconds, the message-1
//! deadline. That timer belongs to hyper's HTTP/1 connection, so a
//! plaintext listener is an HTTP/1 server. HTTP/2 is not a type this
//! module can build and not a feature this crate links: its preface has
//! no header or idle timer, and a peer that finished one would sit idle
//! holding a connection slot. A channel connection does not use this
//! timer for idle — its record stream owns a long idle, so a session is
//! not opened again through a new handshake — and that listener is not
//! built here. A response write that makes no progress for 4 seconds
//! closes the connection. That stall bound is every listener's,
//! including the channel's record stream.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::time::{sleep, Sleep};

use crate::conn_limit::LimitedListener;

/// Header-read, and the plaintext idle, both the message-1 deadline.
pub(crate) const HEADER_READ: Duration = Duration::from_secs(4);

/// A response write that makes no progress for this long is closed.
pub(crate) const WRITE_STALL: Duration = Duration::from_secs(4);

/// Serve `app` on `listener` until `signal` completes. Every connection
/// reads headers within [`HEADER_READ`] and is closed after that long
/// with nothing to read, which is the plaintext idle.
pub(crate) async fn serve_plaintext(
    mut listener: LimitedListener,
    make_service: Router,
    signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let (signal_tx, signal_rx) = watch::channel(());
    tokio::spawn(async move {
        signal.await;
        drop(signal_rx);
    });
    let (close_tx, close_rx) = watch::channel(());
    loop {
        let (io, _remote_addr) = tokio::select! {
            conn = listener.accept() => conn,
            () = signal_tx.closed() => break,
        };
        handle_connection(
            make_service.clone(),
            &signal_tx,
            &close_rx,
            StallWrite::new(io, WRITE_STALL),
        );
    }
    drop(close_rx);
    drop(listener);
    close_tx.closed().await;
    Ok(())
}

fn handle_connection(
    make_service: Router,
    signal_tx: &watch::Sender<()>,
    close_rx: &watch::Receiver<()>,
    io: StallWrite<crate::conn_limit::CountedStream>,
) {
    let io = TokioIo::new(io);
    // `Router<()>` serves `http::Request<Incoming>` directly: its body
    // bound accepts hyper's incoming body.
    let hyper_service = TowerToHyperService::new(make_service);
    let signal_tx = signal_tx.clone();
    let close_rx = close_rx.clone();
    tokio::spawn(async move {
        // HTTP/1 is the connection type. There is no preface sniff and no
        // HTTP/2 arm: a plaintext RPC connection does not upgrade. The
        // timer is what makes the header-read bound real, and on this
        // listener it is also the idle bound: hyper arms it again while
        // waiting for the next request line.
        let mut conn = pin!(plaintext_builder().serve_connection(io, hyper_service));
        let mut signal_closed = pin!(signal_tx.closed());
        let mut shutting_down = false;
        loop {
            tokio::select! {
                result = conn.as_mut() => {
                    if let Err(error) = result {
                        tracing::trace!("failed to serve connection: {error:#}");
                    }
                    break;
                }
                () = &mut signal_closed, if !shutting_down => {
                    shutting_down = true;
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
        drop(close_rx);
    });
}

/// The HTTP/1 connection a plaintext listener serves. [`HEADER_READ`] is
/// the header-read bound, and hyper arms that same timer again while it
/// waits for the next request line, which is the idle bound.
fn plaintext_builder() -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HEADER_READ));
    builder
}

/// Closes a connection whose response write makes no progress for `bound`.
struct StallWrite<T> {
    inner: T,
    bound: Duration,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<T> StallWrite<T> {
    fn new(inner: T, bound: Duration) -> Self {
        Self {
            inner,
            bound,
            wait: None,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if self.wait.is_none() {
            self.wait = Some(Box::pin(sleep(self.bound)));
        }
        let wait = self.wait.as_mut().expect("the stall sleep was just armed");
        if wait.as_mut().poll(cx).is_ready() {
            self.wait = None;
            Poll::Ready(io::Error::new(
                io::ErrorKind::TimedOut,
                "the response write made no progress",
            ))
        } else {
            Poll::Pending
        }
    }

    fn wrote(&mut self) {
        self.wait = None;
    }

    /// One poll of the inner writer. [`Poll::Pending`] arms the stall.
    /// Any [`Poll::Ready`] is progress and clears it, including a
    /// completed write of zero bytes and an error: the wait measures a
    /// writer that has not answered, not a writer that answered empty.
    fn drive<R>(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>>
    where
        T: Unpin,
    {
        match poll(Pin::new(&mut self.inner), cx) {
            Poll::Pending => match self.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            ready => {
                self.wrote();
                ready
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StallWrite<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StallWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .drive(cx, |inner, cx| inner.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive(cx, AsyncWrite::poll_flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive(cx, AsyncWrite::poll_shutdown)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .drive(cx, |inner, cx| inner.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    use axum::routing::get;
    use axum::Router;
    use hyper_util::service::TowerToHyperService;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn app() -> Router {
        Router::new().route("/", get(|| async { "ok" }))
    }

    /// Bytes the test has offered the writer. An empty queue is a writer
    /// that has not answered. `Some(0)` is an empty completion, which is
    /// still an answer.
    struct Hold {
        state: Arc<Mutex<HoldState>>,
    }

    struct HoldState {
        answers: VecDeque<usize>,
        waker: Option<Waker>,
    }

    struct Grant {
        state: Arc<Mutex<HoldState>>,
    }

    impl Grant {
        fn answer(&self, n: usize) {
            let mut state = self.state.lock().expect("the hold");
            state.answers.push_back(n);
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    fn hold() -> (Hold, Grant) {
        let state = Arc::new(Mutex::new(HoldState {
            answers: VecDeque::new(),
            waker: None,
        }));
        (
            Hold {
                state: Arc::clone(&state),
            },
            Grant { state },
        )
    }

    impl AsyncRead for Hold {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Hold {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.get_mut().state.lock().expect("the hold");
            match state.answers.pop_front() {
                Some(0) => Poll::Ready(Ok(0)),
                Some(n) => Poll::Ready(Ok(n.min(buf.len()))),
                None => {
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_with_no_progress_stalls() {
        let (hold, _grant) = hold();
        let mut io = StallWrite::new(hold, WRITE_STALL);
        let task = tokio::spawn(async move { io.write(&[1, 2, 3, 4]).await });
        tokio::task::yield_now().await;
        tokio::time::advance(WRITE_STALL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let error = task
            .await
            .expect("the write task finishes")
            .expect_err("no progress stalls");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_keeps_moving_is_not_a_stall() {
        let (hold, grant) = hold();
        let mut io = StallWrite::new(hold, WRITE_STALL);
        let task = tokio::spawn(async move { io.write_all(&[1, 2, 3, 4]).await });
        tokio::task::yield_now().await;
        for _ in 0..8 {
            if task.is_finished() {
                break;
            }
            tokio::time::advance(Duration::from_secs(3)).await;
            grant.answer(1);
            tokio::task::yield_now().await;
        }
        task.await
            .expect("the write task finishes")
            .expect("slow progress is not a stall");
    }

    /// An empty completion is an answer. The stall measures a writer that
    /// has not returned, so `Ok(0)` starts the wait over: three seconds
    /// later a byte still lands, where a timer that ignored the empty
    /// answer would already have fired.
    #[tokio::test(start_paused = true)]
    async fn an_empty_write_is_progress() {
        let (hold, grant) = hold();
        let mut io = StallWrite::new(hold, WRITE_STALL);
        let task = tokio::spawn(async move {
            let empty = io.write(&[1, 2, 3]).await?;
            let bytes = io.write(&[1, 2, 3]).await?;
            Ok::<(usize, usize), io::Error>((empty, bytes))
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.answer(0);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.answer(3);
        tokio::task::yield_now().await;
        let (empty, bytes) = task
            .await
            .expect("the write task finishes")
            .expect("the empty answer reset the stall");
        assert_eq!(empty, 0);
        assert_eq!(bytes, 3);
    }

    async fn serve_half(server: tokio::io::DuplexStream) -> Result<(), hyper::Error> {
        let server = TokioIo::new(server);
        let service = TowerToHyperService::new(app());
        pin!(plaintext_builder().serve_connection(server, service)).await
    }

    /// One second inside the header bound, so the "still open" check is
    /// taken before the timer fires.
    fn inside_header_bound() -> Duration {
        HEADER_READ
            .checked_sub(Duration::from_secs(1))
            .expect("the header bound is longer than a second")
    }

    #[tokio::test(start_paused = true)]
    async fn an_incomplete_header_closes_at_the_header_bound() {
        let (mut client, server) = tokio::io::duplex(64);
        let serve = tokio::spawn(serve_half(server));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: t\r\n")
            .await
            .expect("the partial request fits the duplex");
        tokio::task::yield_now().await;
        tokio::time::advance(inside_header_bound()).await;
        tokio::task::yield_now().await;
        assert!(!serve.is_finished(), "a second remains on the header bound");
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(
            serve.is_finished(),
            "the header bound closed the connection"
        );
        let result = serve.await.expect("the serve task");
        assert!(result.is_err(), "an incomplete header fails the connection");
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_keep_alive_closes_at_the_header_bound() {
        let (mut client, server) = tokio::io::duplex(1024);
        let serve = tokio::spawn(serve_half(server));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .expect("the request fits the duplex");
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.expect("the response");
        assert!(n > 0, "the request was served");
        tokio::task::yield_now().await;
        tokio::time::advance(inside_header_bound()).await;
        tokio::task::yield_now().await;
        assert!(!serve.is_finished(), "a second remains on the idle bound");
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(serve.is_finished(), "idle closed the connection");
    }
}
