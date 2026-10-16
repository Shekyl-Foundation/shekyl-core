// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Copy socket bytes through the cap.
//!
//! `encode` and `decode` are the connector's framing. An identity pair
//! copies the bytes. A seam seals and opens them. A full queue is
//! selected beside the socket write, so a peer that stops reading does
//! not keep the buffer.

use std::borrow::Cow;

use shekyl_transport_layer::{CloseCause, CloseKind, LinkDirection, MessageClass};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::gate::LinkGate;
use crate::queue::{ByteQueue, Overfull};
use crate::session::InboundEnd;
use crate::stall::WriteStall;

/// Write every byte of `bytes`.
///
/// `Err(wrote)` is how many bytes the socket accepted before it failed
/// or returned zero. A grant refund uses that count: the whole grant
/// when nothing left, and only the unsent tail when a prefix did.
pub async fn write_all_counted<W>(write: &mut W, bytes: &[u8]) -> Result<(), usize>
where
    W: AsyncWrite + Unpin,
{
    write_counted(write, bytes, || {}).await
}

/// Write every byte, and call `on_accept` after each slice the socket took.
///
/// The hook runs before the next attempt. A prefix is therefore visible
/// when a later write in the same grant fails, at the instant that slice
/// was accepted.
async fn write_counted<W, F>(write: &mut W, bytes: &[u8], mut on_accept: F) -> Result<(), usize>
where
    W: AsyncWrite + Unpin,
    F: FnMut(),
{
    let mut wrote = 0usize;
    while wrote < bytes.len() {
        match write.write(&bytes[wrote..]).await {
            Ok(0) | Err(_) => return Err(wrote),
            Ok(n) => {
                wrote += n;
                on_accept();
            }
        }
    }
    Ok(())
}

/// Give back the part of `grant` the socket did not accept.
///
/// Nothing written returns the packet as well as the bytes. A prefix
/// keeps the packet and returns only the tail.
pub fn refund_unsent(
    gate: &LinkGate,
    direction: LinkDirection,
    conn: u64,
    grant: u64,
    wrote: usize,
) {
    let wrote = u64::try_from(wrote).unwrap_or(grant);
    if wrote == 0 {
        gate.refund(direction, conn, grant, true);
    } else if wrote < grant {
        gate.refund(direction, conn, grant - wrote, false);
    }
}

/// Bytes read from the socket in one turn.
///
/// This is not a frame size. The connector's `decode` decides where a
/// frame ends. Both connectors share this buffer so the read size cannot
/// drift between them.
pub const READ_CHUNK_BYTES: usize = 8 * 1024;

/// Write queued bytes until the queue closes or the cap trips.
///
/// `encode` turns one queued buffer into the socket bytes. An empty
/// encoding is not written. The cap count is released when the write
/// finishes, or when it is cancelled.
pub async fn write_capped<W, F>(
    write: &mut W,
    outbound: &ByteQueue,
    overfull: &Overfull,
    gate: &LinkGate,
    stall: &mut WriteStall,
    mut encode: F,
) -> CloseCause
where
    W: AsyncWrite + Unpin,
    F: for<'a> FnMut(&'a [u8]) -> Result<Cow<'a, [u8]>, CloseKind>,
{
    let conn = stall.conn();
    let _lease = gate.lease(LinkDirection::Up, conn);
    let cause = write_queued(write, outbound, overfull, gate, stall, &mut encode).await;
    stall.fold();
    cause
}

async fn write_queued<W, F>(
    write: &mut W,
    outbound: &ByteQueue,
    overfull: &Overfull,
    gate: &LinkGate,
    stall: &mut WriteStall,
    encode: &mut F,
) -> CloseCause
where
    W: AsyncWrite + Unpin,
    F: for<'a> FnMut(&'a [u8]) -> Result<Cow<'a, [u8]>, CloseKind>,
{
    let conn = stall.conn();
    let stamp = gate.byte_stamp(LinkDirection::Up, conn);
    loop {
        if overfull.tripped() {
            shutdown(write).await;
            return CloseCause::new(CloseKind::SendQueueFull);
        }
        tokio::select! {
            biased;
            () = overfull.wait() => {
                shutdown(write).await;
                return CloseCause::new(CloseKind::SendQueueFull);
            }
            next = outbound.pop() => {
                let (class, bytes) = match next {
                    Ok(item) => item,
                    Err(closed) => {
                        shutdown(write).await;
                        return CloseCause::new(closed.kind());
                    }
                };
                let n = bytes.len();
                let wire = match encode(&bytes) {
                    Ok(wire) => wire,
                    Err(kind) => {
                        outbound.release(n);
                        shutdown(write).await;
                        return CloseCause::new(kind);
                    }
                };
                if wire.is_empty() {
                    outbound.release(n);
                    continue;
                }
                let mut off = 0usize;
                while off < wire.len() {
                    if overfull.tripped() {
                        outbound.release(n);
                        shutdown(write).await;
                        return CloseCause::new(CloseKind::SendQueueFull);
                    }
                    let room = wire.len() - off;
                    let grant = gate
                        .acquire(LinkDirection::Up, conn, class, room as u64)
                        .await;
                    let grant = usize::try_from(grant).unwrap_or(room).min(room);
                    if grant == 0 {
                        continue;
                    }
                    let end = off + grant;
                    stall.begin();
                    tokio::select! {
                        biased;
                        () = overfull.wait() => {
                            stall.cancel();
                            gate.refund(LinkDirection::Up, conn, grant as u64, true);
                            outbound.release(n);
                            shutdown(write).await;
                            return CloseCause::new(CloseKind::SendQueueFull);
                        }
                        result = write_counted(write, &wire[off..end], || stamp.store()) => {
                            stall.complete();
                            if let Err(wrote) = result {
                                refund_unsent(gate, LinkDirection::Up, conn, grant as u64, wrote);
                                outbound.release(n);
                                shutdown(write).await;
                                return CloseCause::new(CloseKind::IoError);
                            }
                        }
                    }
                    off = end;
                }
                gate.record_message(LinkDirection::Up, conn);
                outbound.release(n);
            }
        }
    }
}

/// Read socket bytes until the peer, the cap, or the caller stops.
///
/// `decode` turns one read into session frames. A slow [`crate::Session::recv`]
/// stops this function on a full inbound queue, and TCP pushes back on
/// the peer. A tripped cap closes instead of waiting that out.
pub async fn read_capped<R, F>(
    read: &mut R,
    inbound: InboundEnd,
    overfull: &Overfull,
    gate: &LinkGate,
    conn: u64,
    mut decode: F,
) -> CloseCause
where
    R: AsyncRead + Unpin,
    F: FnMut(&[u8]) -> Result<Vec<Vec<u8>>, CloseKind>,
{
    let _lease = gate.lease(LinkDirection::Down, conn);
    let cause = read_queued(read, &inbound, overfull, gate, conn, &mut decode).await;
    inbound.close(cause);
    cause
}

async fn read_queued<R, F>(
    read: &mut R,
    inbound: &InboundEnd,
    overfull: &Overfull,
    gate: &LinkGate,
    conn: u64,
    decode: &mut F,
) -> CloseCause
where
    R: AsyncRead + Unpin,
    F: FnMut(&[u8]) -> Result<Vec<Vec<u8>>, CloseKind>,
{
    let mut buf = [0u8; READ_CHUNK_BYTES];
    let stamp = gate.byte_stamp(LinkDirection::Down, conn);
    loop {
        if overfull.tripped() {
            return CloseCause::new(CloseKind::SendQueueFull);
        }
        let grant = tokio::select! {
            biased;
            () = overfull.wait() => return CloseCause::new(CloseKind::SendQueueFull),
            grant = gate.acquire(LinkDirection::Down, conn, MessageClass::Session, buf.len() as u64) => grant,
        };
        let room = usize::try_from(grant).unwrap_or(buf.len()).min(buf.len());
        if room == 0 {
            continue;
        }
        let n = tokio::select! {
            biased;
            () = overfull.wait() => {
                gate.refund(LinkDirection::Down, conn, grant, true);
                return CloseCause::new(CloseKind::SendQueueFull);
            }
            result = read.read(&mut buf[..room]) => match result {
                Ok(0) => {
                    gate.refund(LinkDirection::Down, conn, grant, true);
                    return CloseCause::new(CloseKind::PeerClosed);
                }
                Ok(n) => {
                    if n > 0 {
                        stamp.store();
                    }
                    n
                }
                Err(_) => {
                    gate.refund(LinkDirection::Down, conn, grant, true);
                    return CloseCause::new(CloseKind::IoError);
                }
            },
        };
        if (n as u64) < grant {
            gate.refund(LinkDirection::Down, conn, grant - n as u64, false);
        }
        gate.record_message(LinkDirection::Down, conn);
        let pieces = match decode(&buf[..n]) {
            Ok(pieces) => pieces,
            Err(kind) => return CloseCause::new(kind),
        };
        for piece in pieces {
            tokio::select! {
                biased;
                () = overfull.wait() => return CloseCause::new(CloseKind::SendQueueFull),
                result = inbound.send(piece) => {
                    if result.is_err() {
                        return CloseCause::new(CloseKind::LocalClose);
                    }
                }
            }
        }
    }
}

async fn shutdown<W: AsyncWrite + Unpin>(write: &mut W) {
    drop(write.shutdown().await);
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use shekyl_transport_layer::CloseKind;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::{read_capped, write_capped};
    use crate::gate::LinkGate;
    use crate::queue::{ByteQueue, Overfull, PushError};
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

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
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

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
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

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for StuckRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.entered.store(true, Ordering::Release);
            Poll::Pending
        }
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
}
