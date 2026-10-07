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
use std::fmt;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use shekyl_transport_layer::{CloseCause, CloseKind, LinkDirection, MessageClass};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::gate::LinkGate;
use crate::queue::{ByteQueue, Overfull};

/// Write every byte of `bytes`.
///
/// `Err(wrote)` is how many bytes the socket accepted before it failed
/// or returned zero. A grant refund uses that count: the whole grant
/// when nothing left, and only the unsent tail when a prefix did.
pub async fn write_all_counted<W>(write: &mut W, bytes: &[u8]) -> Result<(), usize>
where
    W: AsyncWrite + Unpin,
{
    let mut wrote = 0usize;
    while wrote < bytes.len() {
        match write.write(&bytes[wrote..]).await {
            Ok(0) | Err(_) => return Err(wrote),
            Ok(n) => wrote += n,
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

/// Power-of-two nanosecond buckets for one session's socket writes.
///
/// Bucket `i` counts writes whose elapsed time is in `[2^i, 2^(i+1))`
/// nanoseconds. Zero nanoseconds is bucket 0. The longest sample is
/// `max_ns`. A write cancelled before it returned is
/// `in_flight_at_close_ns`, not a bucket: it did not finish.
///
/// The writer task owns this. Nothing on the write path takes a
/// process-wide lock. [`WriteStall::fold`] adds the buckets to the
/// process histogram once, when the session's writer finishes.
pub struct WriteStall {
    conn: u64,
    buckets: [u64; 64],
    max_ns: u64,
    in_flight_at_close_ns: Option<u64>,
    started: Option<Instant>,
    folded: bool,
}

impl WriteStall {
    #[must_use]
    pub fn new(conn: u64) -> Self {
        Self {
            conn,
            buckets: [0; 64],
            max_ns: 0,
            in_flight_at_close_ns: None,
            started: None,
            folded: false,
        }
    }

    #[must_use]
    pub fn conn(&self) -> u64 {
        self.conn
    }

    #[must_use]
    pub fn max_ns(&self) -> u64 {
        self.max_ns
    }

    #[must_use]
    pub fn buckets(&self) -> &[u64; 64] {
        &self.buckets
    }

    #[must_use]
    pub fn in_flight_at_close_ns(&self) -> Option<u64> {
        self.in_flight_at_close_ns
    }

    fn begin(&mut self) {
        self.started = Some(Instant::now());
    }

    fn complete(&mut self) {
        if let Some(started) = self.started.take() {
            self.record_ns(ns_of(started.elapsed()));
        }
    }

    fn cancel(&mut self) {
        if let Some(started) = self.started.take() {
            self.in_flight_at_close_ns = Some(ns_of(started.elapsed()));
        }
    }

    fn record_ns(&mut self, ns: u64) {
        self.buckets[bucket_of(ns)] = self.buckets[bucket_of(ns)].saturating_add(1);
        if ns > self.max_ns {
            self.max_ns = ns;
        }
    }

    /// Add this session's buckets to the process histogram. A second call
    /// does not add them again.
    pub fn fold(&mut self) {
        if self.folded {
            return;
        }
        self.cancel();
        self.folded = true;
        process_stalls()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .add(self);
    }
}

impl Drop for WriteStall {
    fn drop(&mut self) {
        self.fold();
    }
}

impl fmt::Display for WriteStall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "max_ns={} in_flight_ns={}",
            self.max_ns,
            self.in_flight_at_close_ns.unwrap_or(0)
        )?;
        for (index, count) in self.buckets.iter().copied().enumerate() {
            if count != 0 {
                write!(f, " {index}:{count}")?;
            }
        }
        Ok(())
    }
}

/// The process-wide fold of every session histogram. This is the D9
/// record: the distribution, not a threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessWriteStall {
    pub buckets: [u64; 64],
    pub max_ns: u64,
    pub closes: u64,
    pub in_flight_at_close: u64,
    pub in_flight_at_close_max_ns: u64,
}

impl ProcessWriteStall {
    fn add(&mut self, stall: &WriteStall) {
        for (into, from) in self.buckets.iter_mut().zip(stall.buckets) {
            *into = into.saturating_add(from);
        }
        if stall.max_ns > self.max_ns {
            self.max_ns = stall.max_ns;
        }
        self.closes = self.closes.saturating_add(1);
        if let Some(ns) = stall.in_flight_at_close_ns {
            self.in_flight_at_close = self.in_flight_at_close.saturating_add(1);
            if ns > self.in_flight_at_close_max_ns {
                self.in_flight_at_close_max_ns = ns;
            }
        }
    }
}

fn process_stalls() -> &'static Mutex<ProcessWriteStall> {
    static STALLS: OnceLock<Mutex<ProcessWriteStall>> = OnceLock::new();
    STALLS.get_or_init(|| {
        Mutex::new(ProcessWriteStall {
            buckets: [0; 64],
            max_ns: 0,
            closes: 0,
            in_flight_at_close: 0,
            in_flight_at_close_max_ns: 0,
        })
    })
}

/// The histograms folded so far. A reader takes this after a session's
/// writer has finished; the per-session record is still on that
/// [`WriteStall`].
#[must_use]
pub fn process_write_stall() -> ProcessWriteStall {
    process_stalls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn ns_of(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// Bucket `i` is `[2^i, 2^(i+1))` nanoseconds. Zero is bucket 0.
fn bucket_of(ns: u64) -> usize {
    if ns == 0 {
        0
    } else {
        (63 - ns.leading_zeros()) as usize
    }
}

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
    let cause = write_queued(write, outbound, overfull, gate, stall, &mut encode).await;
    gate.leave(LinkDirection::Up, conn);
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
                        result = write_all_counted(write, &wire[off..end]) => {
                            stall.complete();
                            if result.is_ok() {
                                gate.touch(LinkDirection::Up, conn);
                            }
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
    inbound: mpsc::Sender<Vec<u8>>,
    overfull: &Overfull,
    gate: &LinkGate,
    conn: u64,
    mut decode: F,
) -> CloseCause
where
    R: AsyncRead + Unpin,
    F: FnMut(&[u8]) -> Result<Vec<Vec<u8>>, CloseKind>,
{
    let cause = read_queued(read, inbound, overfull, gate, conn, &mut decode).await;
    gate.leave(LinkDirection::Down, conn);
    cause
}

async fn read_queued<R, F>(
    read: &mut R,
    inbound: mpsc::Sender<Vec<u8>>,
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
                        gate.touch(LinkDirection::Down, conn);
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

    use super::{process_write_stall, read_capped, write_capped, WriteStall};
    use crate::gate::LinkGate;
    use crate::queue::{ByteQueue, Overfull, PushError};
    use crate::UNREAD_FRAMES;

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
        assert_eq!(after.closes, before.closes + 1);
        assert!(after.max_ns >= max_ns);
    }

    #[test]
    fn buckets_are_powers_of_two() {
        let mut stall = WriteStall::new(0);
        stall.record_ns(0);
        stall.record_ns(1);
        stall.record_ns(2);
        stall.record_ns(1 << 10);
        assert_eq!(stall.buckets()[0], 2);
        assert_eq!(stall.buckets()[1], 1);
        assert_eq!(stall.buckets()[10], 1);
        assert_eq!(stall.max_ns(), 1 << 10);
        // Not folded: this stall is the table, not a session close.
        stall.folded = true;
    }

    #[tokio::test]
    async fn a_full_queue_cancels_a_blocked_read() {
        let entered = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&entered);
        let overfull = Arc::new(Overfull::new());
        let trip = Arc::clone(&overfull);
        let (inbound, _rx) = tokio::sync::mpsc::channel(UNREAD_FRAMES);
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
}
