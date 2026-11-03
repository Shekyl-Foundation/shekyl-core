// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP serving for a plaintext listener, with the timeouts §6.3's step 2
//! records.
//!
//! Header-read and idle are one hyper timer: 4 seconds, the message-1
//! deadline. That timer is HTTP/1's, so a plaintext listener speaks
//! HTTP/1 only. HTTP/2 has no equivalent on this builder, and a peer
//! that finished its preface would sit idle holding a connection slot.
//! A channel connection does not use this timer for idle — its record
//! stream owns a long idle, so a session is not opened again through a
//! new handshake — and that listener is not built here. A response write
//! that makes no progress for 4 seconds closes the connection. That
//! stall bound is every listener's, including the channel's record
//! stream.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
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
        // HTTP/1 only. `http1_only` is ignored by
        // `serve_connection_with_upgrades`, which sniffs an HTTP/2 preface
        // and then has no header or idle timer. Plaintext RPC has no
        // upgrade.
        let mut builder = Builder::new(TokioExecutor::new()).http1_only();
        // The timer is what makes the header-read bound real. On a
        // plaintext listener it is also the idle bound: hyper arms it
        // again while waiting for the next request line.
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(HEADER_READ));
        let mut conn = pin!(builder.serve_connection(io, hyper_service));
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
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => match this.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            other => {
                this.wrote();
                other
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => match this.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            other => {
                this.wrote();
                other
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => match this.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            other => {
                this.wrote();
                other
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => match this.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            other => {
                this.wrote();
                other
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
