// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The read and write stalls measure progress, not the whole record.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{bytes, directions, RecordStream};

struct Gate {
    inner: Arc<Mutex<GateInner>>,
}

struct GateInner {
    inbound: Vec<u8>,
    read_at: usize,
    read_room: usize,
    read_waker: Option<Waker>,
    write_room: usize,
    write_waker: Option<Waker>,
}

struct Grant {
    inner: Arc<Mutex<GateInner>>,
}

impl Grant {
    fn write(&self, n: usize) {
        let mut gate = self.inner.lock().expect("gate");
        gate.write_room += n;
        if let Some(waker) = gate.write_waker.take() {
            waker.wake();
        }
    }

    fn read(&self, n: usize) {
        let mut gate = self.inner.lock().expect("gate");
        gate.read_room += n;
        if let Some(waker) = gate.read_waker.take() {
            waker.wake();
        }
    }
}

impl Gate {
    fn new(inbound: Vec<u8>) -> (Self, Grant) {
        let inner = Arc::new(Mutex::new(GateInner {
            inbound,
            read_at: 0,
            read_room: 0,
            read_waker: None,
            write_room: 0,
            write_waker: None,
        }));
        (
            Self {
                inner: Arc::clone(&inner),
            },
            Grant { inner },
        )
    }
}

impl AsyncRead for Gate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut gate = self.inner.lock().expect("gate");
        if gate.read_room == 0 || gate.read_at >= gate.inbound.len() {
            gate.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = 1.min(buf.remaining());
        buf.put_slice(&gate.inbound[gate.read_at..gate.read_at + n]);
        gate.read_at += n;
        gate.read_room -= 1;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Gate {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut gate = self.inner.lock().expect("gate");
        if gate.write_room == 0 || buf.is_empty() {
            gate.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        gate.write_room -= 1;
        Poll::Ready(Ok(1.min(buf.len())))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let buf = bufs.iter().find(|buf| !buf.is_empty()).map(|buf| &buf[..]);
        match buf {
            Some(buf) => self.poll_write(cx, buf),
            None => Poll::Ready(Ok(0)),
        }
    }
}

/// One byte every three seconds is progress. The four-second stall must
/// not fire across a drain that keeps moving.
#[tokio::test(start_paused = true)]
async fn a_write_that_keeps_moving_is_not_a_stall() {
    let (gate, grant) = Gate::new(Vec::new());
    let ((send, recv), _) = directions();
    let mut client = RecordStream::new(gate, send, recv);
    let message = bytes(32);
    let task = tokio::spawn(async move {
        client.write_all(&message).await?;
        client.flush().await?;
        Ok::<(), io::Error>(())
    });
    tokio::task::yield_now().await;
    for _ in 0..2_000 {
        if task.is_finished() {
            break;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.write(1);
        tokio::task::yield_now().await;
    }
    task.await
        .expect("the write task finishes")
        .expect("slow progress is not a stall");
}

/// Nothing accepted for four seconds is a stall.
#[tokio::test(start_paused = true)]
async fn a_write_with_no_progress_stalls() {
    let (gate, _grant) = Gate::new(Vec::new());
    let ((send, recv), _) = directions();
    let mut client = RecordStream::new(gate, send, recv);
    let message = bytes(32);
    let task = tokio::spawn(async move {
        client.write_all(&message).await?;
        client.flush().await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let error = task
        .await
        .expect("the write task finishes")
        .expect_err("no progress stalls");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

/// Ciphertext arriving one byte at a time still assembles the record.
#[tokio::test(start_paused = true)]
async fn a_read_that_keeps_moving_is_not_a_stall() {
    let plain = bytes(32);
    let ((c_send, c_recv), (d_send, d_recv)) = directions();
    let (client_io, mut raw) = tokio::io::duplex(1 << 16);
    let mut client = RecordStream::new(client_io, c_send, c_recv);
    client.write_all(&plain).await.expect("seal");
    client.flush().await.expect("flush");
    drop(client);
    let mut inbound = Vec::new();
    let mut buf = [0u8; 1024];
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        let mut read = ReadBuf::new(&mut buf);
        match Pin::new(&mut raw).poll_read(&mut cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let n = read.filled().len();
                if n == 0 {
                    break;
                }
                inbound.extend_from_slice(&buf[..n]);
            }
            Poll::Pending => break,
            Poll::Ready(Err(error)) => panic!("{error}"),
        }
    }
    assert!(
        !inbound.is_empty(),
        "the sealed record reached the transport"
    );
    let (gate, grant) = Gate::new(inbound);
    let mut daemon = RecordStream::new(gate, d_send, d_recv);
    let expect = plain.clone();
    let task = tokio::spawn(async move {
        let mut got = vec![0u8; expect.len()];
        daemon.read_exact(&mut got).await?;
        Ok::<Vec<u8>, io::Error>(got)
    });
    tokio::task::yield_now().await;
    for _ in 0..2_000 {
        if task.is_finished() {
            break;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.read(1);
        tokio::task::yield_now().await;
    }
    let got = task
        .await
        .expect("the read task finishes")
        .expect("slow ciphertext is not a stall");
    assert_eq!(got, plain);
}

/// Shutdown writes the close record through the same drain as a response.
/// No accepted byte for four seconds is the write stall.
#[tokio::test(start_paused = true)]
async fn a_shutdown_with_no_progress_stalls() {
    let (gate, _grant) = Gate::new(Vec::new());
    let ((send, recv), _) = directions();
    let mut client = RecordStream::new(gate, send, recv);
    let task = tokio::spawn(async move { client.shutdown().await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let error = task
        .await
        .expect("the shutdown task finishes")
        .expect_err("no progress stalls");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

/// One byte of the close record every three seconds is progress. The
/// stall is four seconds without a byte, so a moving shutdown finishes.
#[tokio::test(start_paused = true)]
async fn a_shutdown_that_keeps_moving_is_not_a_stall() {
    let (gate, grant) = Gate::new(Vec::new());
    let ((send, recv), _) = directions();
    let mut client = RecordStream::new(gate, send, recv);
    let task = tokio::spawn(async move { client.shutdown().await });
    tokio::task::yield_now().await;
    for _ in 0..2_000 {
        if task.is_finished() {
            break;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.write(1);
        tokio::task::yield_now().await;
    }
    task.await
        .expect("the shutdown task finishes")
        .expect("slow progress is not a stall");
}
