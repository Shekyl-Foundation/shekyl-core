// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use shekyl_transport_layer::{CloseKind, LinkDirection, MessageClass};
use tokio::io::AsyncWrite;

use super::{read_capped, write_capped, write_granted};
use crate::gate::LinkGate;
use crate::queue::{ByteQueue, Overfull, PushError};
use crate::read::ReadyRead;
use crate::stall::{process_write_stall, WriteStall};

struct StuckWrite {
    entered: Arc<AtomicBool>,
}

impl AsyncWrite for StuckWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.entered.store(true, Ordering::Release);
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Pending once, then the whole buffer. The gap is the stall.
struct DelayWrite {
    entered: Arc<AtomicBool>,
    waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
}

impl AsyncWrite for DelayWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.entered.load(Ordering::Acquire) {
            self.entered.store(true, Ordering::Release);
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct StuckRead {
    entered: Arc<AtomicBool>,
}

/// Accepts `limit` bytes, then fails. The flag is read on the failing poll,
/// which is after any accepted slice has had its chance to stamp.
struct PrefixThenFail {
    taken: usize,
    limit: usize,
    gate: LinkGate,
    conn: u64,
    stamped_before_error: bool,
}

impl AsyncWrite for PrefixThenFail {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        if this.taken >= this.limit {
            this.stamped_before_error = this.gate.activity(this.conn).0 > 0;
            return Poll::Ready(Err(std::io::Error::other("stopped")));
        }
        let n = buf.len().min(this.limit - this.taken);
        this.taken += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl ReadyRead for StuckRead {
    fn wait_readable(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> + '_ {
        std::future::poll_fn(|_cx| {
            self.entered.store(true, Ordering::Release);
            Poll::Pending
        })
    }

    fn try_read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "stuck"))
    }
}

/// Bytes the test pushes, and a flag set when a read finds the pipe empty.
#[derive(Clone)]
struct Pipe {
    incoming: Arc<Mutex<VecDeque<u8>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    waiting: Arc<AtomicBool>,
}

impl Pipe {
    fn new() -> Self {
        Self {
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            waker: Arc::new(Mutex::new(None)),
            waiting: Arc::new(AtomicBool::new(false)),
        }
    }

    fn push(&self, bytes: &[u8]) {
        self.incoming.lock().expect("pipe").extend(bytes);
        self.waiting.store(false, Ordering::Release);
        if let Some(waker) = self.waker.lock().expect("pipe").take() {
            waker.wake();
        }
    }

    fn len(&self) -> usize {
        self.incoming.lock().expect("pipe").len()
    }
}

impl ReadyRead for Pipe {
    fn wait_readable(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> + '_ {
        std::future::poll_fn(|cx| {
            if self.incoming.lock().expect("pipe").is_empty() {
                self.waiting.store(true, Ordering::Release);
                *self.waker.lock().expect("pipe") = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        })
    }

    fn try_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut incoming = self.incoming.lock().expect("pipe");
        if incoming.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
        }
        let n = buf.len().min(incoming.len());
        for slot in &mut buf[..n] {
            *slot = incoming.pop_front().expect("byte");
        }
        Ok(n)
    }
}

fn freeze(gate: &LinkGate) {
    gate.install_clock(Arc::new(|| 0));
}

async fn until_entered(flag: &AtomicBool) {
    let start = std::time::Instant::now();
    while !flag.load(Ordering::Acquire) {
        assert!(start.elapsed() < Duration::from_secs(2), "socket call");
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_full_queue_cancels_a_blocked_write() {
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let queue = ByteQueue::new(8);
    let sender = queue.clone();
    let overfull = queue.overfull();
    queue.try_push(b"abcdefgh".to_vec()).expect("queue");
    let task = tokio::spawn(async move {
        let mut write = StuckWrite { entered: flag };
        let gate = LinkGate::new();
        let mut stall = WriteStall::new(1);
        let cause = write_capped(&mut write, &queue, &overfull, &gate, &mut stall, |plain| {
            Ok(std::borrow::Cow::Borrowed(plain))
        })
        .await;
        (cause, stall)
    });
    until_entered(&entered).await;
    // The eight bytes are still counted while the write is stuck.
    assert_eq!(sender.try_push(b"x".to_vec()), Err(PushError::Full));
    let (cause, stall) = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("writer finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::SendQueueFull);
    // The socket write had started and was cancelled. It is the
    // in-flight sample, not a completed-write bucket.
    assert!(stall.in_flight_at_close_ns().is_some());
    assert_eq!(stall.buckets().iter().sum::<u64>(), 0);
}

/// A writer waiting on an empty queue reports the overflow that
/// closes it, not a local close: it reads the queue's reason, set with
/// the close.
#[tokio::test]
async fn a_writer_waiting_on_an_empty_queue_reports_the_overflow() {
    let queue = ByteQueue::new(0);
    let sender = queue.clone();
    let overfull = queue.overfull();
    let task = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let gate = LinkGate::new();
        let mut stall = WriteStall::new(1);
        write_capped(&mut sink, &queue, &overfull, &gate, &mut stall, |plain| {
            Ok(std::borrow::Cow::Borrowed(plain))
        })
        .await
    });
    tokio::task::yield_now().await;
    assert_eq!(sender.try_push(b"x".to_vec()), Err(PushError::Full));
    let cause = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("writer finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::SendQueueFull);
}

/// Closing from an end is a local close.
#[tokio::test]
async fn a_writer_waiting_on_a_closed_queue_reports_a_local_close() {
    let queue = ByteQueue::new(8);
    let closer = queue.clone();
    let overfull = queue.overfull();
    let task = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        let gate = LinkGate::new();
        let mut stall = WriteStall::new(1);
        write_capped(&mut sink, &queue, &overfull, &gate, &mut stall, |plain| {
            Ok(std::borrow::Cow::Borrowed(plain))
        })
        .await
    });
    tokio::task::yield_now().await;
    closer.close();
    let cause = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("writer finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::LocalClose);
}

/// One delayed socket write lands in one power-of-two bucket. The max
/// is that sample. The process histogram is what a later reader sees
/// after the writer finishes. This does not cover a write cancelled
/// mid-flight; `a_full_queue_cancels_a_blocked_write` does.
#[tokio::test]
async fn a_delayed_write_is_a_bucket_and_the_max() {
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let slot: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));
    let parked = Arc::clone(&slot);
    let queue = ByteQueue::new(8);
    let closer = queue.clone();
    let overfull = queue.overfull();
    queue.try_push(b"abcd".to_vec()).expect("queue");
    let before = process_write_stall();
    let task = tokio::spawn(async move {
        let mut write = DelayWrite {
            entered: flag,
            waker: parked,
        };
        let gate = LinkGate::new();
        let mut stall = WriteStall::new(41);
        let cause = write_capped(&mut write, &queue, &overfull, &gate, &mut stall, |plain| {
            Ok(std::borrow::Cow::Borrowed(plain))
        })
        .await;
        (cause, stall.max_ns(), stall.buckets().iter().sum::<u64>())
    });
    until_entered(&entered).await;
    std::thread::sleep(Duration::from_millis(20));
    slot.lock().unwrap().take().expect("waker").wake();
    closer.close();
    let (cause, max_ns, samples) = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("writer finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::LocalClose);
    assert!(max_ns > 0);
    assert_eq!(samples, 1);
    let after = process_write_stall();
    // The histogram is process-wide. Another test can fold during the
    // delay, so the total grows by at least this write, not by exactly one.
    assert!(after.closes > before.closes);
    assert!(after.max_ns >= max_ns);
}

#[tokio::test]
async fn a_full_queue_cancels_a_blocked_read() {
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let overfull = Arc::new(Overfull::new());
    let trip = Arc::clone(&overfull);
    let inbound = crate::StreamEnds::open(64).inbound;
    let task = tokio::spawn(async move {
        let mut read = StuckRead { entered: flag };
        let gate = LinkGate::new();
        read_capped(&mut read, inbound, &overfull, &gate, 1, |chunk| {
            Ok(vec![chunk.to_vec()])
        })
        .await
    });
    until_entered(&entered).await;
    trip.trip();
    let cause = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("reader finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::SendQueueFull);
}

/// A reader waits for its peer with no tokens, and counts only what landed.
#[tokio::test]
async fn a_reader_waiting_for_its_peer_holds_no_tokens_and_counts_only_what_landed() {
    const RATE: u64 = 8 * 1024;
    const SENT: usize = 100;
    let gate = LinkGate::new();
    freeze(&gate);
    gate.set_down(Some(RATE));
    let ends = crate::StreamEnds::open(64);
    let pipe = Pipe::new();
    let peer = pipe.clone();
    let waiting = Arc::clone(&pipe.waiting);
    let overfull = Arc::new(Overfull::new());
    let reader_gate = gate.clone();
    let inbound = ends.inbound;
    let task = tokio::spawn(async move {
        let mut local = pipe;
        read_capped(&mut local, inbound, &overfull, &reader_gate, 1, |chunk| {
            Ok(vec![chunk.to_vec()])
        })
        .await
    });
    until_entered(&waiting).await;
    peer.push(&[7u8; SENT]);
    until_entered(&waiting).await;
    assert_eq!(gate.connection(1).bytes_down, SENT as u64);
    let other = gate
        .acquire(
            LinkDirection::Down,
            2,
            MessageClass::Session,
            RATE - SENT as u64,
        )
        .await;
    assert_eq!(other, RATE - SENT as u64);
    task.abort();
    drop(ends.session);
}

/// Two sockets are readable at once. One grant is in a read; the other
/// connection's bytes stay in its pipe.
#[tokio::test]
async fn two_ready_readers_share_one_bucket() {
    let rate = super::READ_CHUNK_BYTES as u64;
    let gate = LinkGate::new();
    freeze(&gate);
    gate.set_down(Some(rate));
    let ends_a = crate::StreamEnds::open(64);
    let ends_b = crate::StreamEnds::open(64);
    let pipe_a = Pipe::new();
    let pipe_b = Pipe::new();
    pipe_a.push(&vec![1u8; super::READ_CHUNK_BYTES]);
    pipe_b.push(&vec![2u8; super::READ_CHUNK_BYTES]);
    let watch_a = pipe_a.clone();
    let watch_b = pipe_b.clone();
    let overfull_a = Arc::new(Overfull::new());
    let overfull_b = Arc::new(Overfull::new());
    let gate_a = gate.clone();
    let gate_b = gate.clone();
    let inbound_a = ends_a.inbound;
    let inbound_b = ends_b.inbound;
    let task_a = tokio::spawn(async move {
        let mut local = pipe_a;
        read_capped(&mut local, inbound_a, &overfull_a, &gate_a, 1, |chunk| {
            Ok(vec![chunk.to_vec()])
        })
        .await
    });
    let task_b = tokio::spawn(async move {
        let mut local = pipe_b;
        read_capped(&mut local, inbound_b, &overfull_b, &gate_b, 2, |chunk| {
            Ok(vec![chunk.to_vec()])
        })
        .await
    });
    let start = std::time::Instant::now();
    loop {
        let down_a = gate.connection(1).bytes_down;
        let down_b = gate.connection(2).bytes_down;
        let a_holds = watch_a.len() == super::READ_CHUNK_BYTES && down_a == 0 && down_b == rate;
        let b_holds = watch_b.len() == super::READ_CHUNK_BYTES && down_b == 0 && down_a == rate;
        if a_holds || b_holds {
            break;
        }
        assert!(down_a + down_b <= rate, "two readers drew one bucket");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the second reader drew"
        );
        tokio::task::yield_now().await;
    }
    task_a.abort();
    task_b.abort();
    drop(ends_a.session);
    drop(ends_b.session);
}

#[tokio::test]
async fn aborting_a_stuck_write_releases_the_stamp() {
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let gate = LinkGate::new();
    let gate_task = gate.clone();
    let queue = ByteQueue::new(8);
    queue.try_push(b"abcd".to_vec()).expect("queue");
    let overfull = queue.overfull();
    let task = tokio::spawn(async move {
        let mut write = StuckWrite { entered: flag };
        let mut stall = WriteStall::new(1);
        write_capped(
            &mut write,
            &queue,
            &overfull,
            &gate_task,
            &mut stall,
            |plain| Ok(std::borrow::Cow::Borrowed(plain)),
        )
        .await
    });
    until_entered(&entered).await;
    assert_eq!(gate.held_stamps(), 1);
    task.abort();
    task.await.expect_err("aborted");
    assert_eq!(gate.held_stamps(), 0);
}

#[tokio::test]
async fn aborting_a_stuck_read_releases_the_stamp() {
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let gate = LinkGate::new();
    let gate_task = gate.clone();
    let overfull = Arc::new(Overfull::new());
    let inbound = crate::StreamEnds::open(64).inbound;
    let task = tokio::spawn(async move {
        let mut read = StuckRead { entered: flag };
        read_capped(&mut read, inbound, &overfull, &gate_task, 1, |chunk| {
            Ok(vec![chunk.to_vec()])
        })
        .await
    });
    until_entered(&entered).await;
    assert_eq!(gate.held_stamps(), 1);
    task.abort();
    task.await.expect_err("aborted");
    assert_eq!(gate.held_stamps(), 0);
}

#[tokio::test]
async fn a_prefix_before_an_error_stamps_the_send() {
    let queue = ByteQueue::new(64);
    queue.try_push(b"abcdef".to_vec()).expect("queue");
    let overfull = queue.overfull();
    let gate = LinkGate::new();
    let mut stall = WriteStall::new(7);
    let mut write = PrefixThenFail {
        taken: 0,
        limit: 2,
        gate: gate.clone(),
        conn: 7,
        stamped_before_error: false,
    };
    let cause = write_capped(&mut write, &queue, &overfull, &gate, &mut stall, |plain| {
        Ok(std::borrow::Cow::Borrowed(plain))
    })
    .await;
    assert_eq!(cause.kind(), CloseKind::IoError);
    assert!(write.stamped_before_error);
}

#[tokio::test]
async fn a_write_that_accepts_nothing_does_not_stamp() {
    let queue = ByteQueue::new(64);
    queue.try_push(b"abcdef".to_vec()).expect("queue");
    let overfull = queue.overfull();
    let gate = LinkGate::new();
    let mut stall = WriteStall::new(7);
    let mut write = PrefixThenFail {
        taken: 0,
        limit: 0,
        gate: gate.clone(),
        conn: 7,
        stamped_before_error: false,
    };
    let cause = write_capped(&mut write, &queue, &overfull, &gate, &mut stall, |plain| {
        Ok(std::borrow::Cow::Borrowed(plain))
    })
    .await;
    assert_eq!(cause.kind(), CloseKind::IoError);
    assert!(!write.stamped_before_error);
}

/// Accepts `limit` bytes, then stays pending so a cancel can land
/// after a prefix.
struct AcceptThenPend {
    taken: usize,
    limit: usize,
    entered: Arc<AtomicBool>,
}

impl AsyncWrite for AcceptThenPend {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        if this.taken < this.limit {
            let n = buf.len().min(this.limit - this.taken);
            this.taken += n;
            return Poll::Ready(Ok(n));
        }
        this.entered.store(true, Ordering::Release);
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// A write cancelled after a prefix counts that prefix and returns the
/// rest of the grant. This is the handshake deadline, which drops the
/// write while a grant is held.
#[tokio::test]
async fn aborting_a_partial_write_returns_the_untaken_grant() {
    const MESSAGE: usize = 8;
    const TOOK: usize = 3;
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let gate = LinkGate::new();
    freeze(&gate);
    gate.set_up(Some(MESSAGE as u64));
    let gate_task = gate.clone();
    let task = tokio::spawn(async move {
        let mut write = AcceptThenPend {
            taken: 0,
            limit: TOOK,
            entered: flag,
        };
        write_granted(
            &mut write,
            &[b'a'; MESSAGE],
            &gate_task,
            4,
            MessageClass::Session,
        )
        .await
    });
    until_entered(&entered).await;
    task.abort();
    task.await.expect_err("aborted");
    assert_eq!(gate.connection(4).bytes_up, TOOK as u64);
    let rest = gate
        .acquire(LinkDirection::Up, 5, MessageClass::Session, MESSAGE as u64)
        .await;
    assert_eq!(rest, (MESSAGE - TOOK) as u64);
}

/// The session writer's overflow arm is the same drop: a prefix already
/// accepted stays counted, and the untaken tail is back in the bucket.
#[tokio::test]
async fn a_cancelled_prefix_returns_the_untaken_grant() {
    const MESSAGE: usize = 8;
    const TOOK: usize = 3;
    let entered = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&entered);
    let gate = LinkGate::new();
    freeze(&gate);
    gate.set_up(Some(MESSAGE as u64));
    let queue = ByteQueue::new(64);
    queue.try_push(vec![b'a'; MESSAGE]).expect("queue");
    let overfull = queue.overfull();
    let trip = Arc::clone(&overfull);
    let gate_task = gate.clone();
    let task = tokio::spawn(async move {
        let mut write = AcceptThenPend {
            taken: 0,
            limit: TOOK,
            entered: flag,
        };
        let mut stall = WriteStall::new(7);
        write_capped(
            &mut write,
            &queue,
            &overfull,
            &gate_task,
            &mut stall,
            |plain| Ok(std::borrow::Cow::Borrowed(plain)),
        )
        .await
    });
    until_entered(&entered).await;
    trip.trip();
    let cause = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("writer finished")
        .expect("joined");
    assert_eq!(cause.kind(), CloseKind::SendQueueFull);
    assert_eq!(gate.connection(7).bytes_up, TOOK as u64);
    let rest = gate
        .acquire(LinkDirection::Up, 8, MessageClass::Session, MESSAGE as u64)
        .await;
    assert_eq!(rest, (MESSAGE - TOOK) as u64);
}
