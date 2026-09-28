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

use shekyl_transport_layer::{CloseCause, CloseKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::queue::{ByteQueue, Overfull};

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
    mut encode: F,
) -> CloseCause
where
    W: AsyncWrite + Unpin,
    F: for<'a> FnMut(&'a [u8]) -> Result<Cow<'a, [u8]>, CloseKind>,
{
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
                let Some(bytes) = next else {
                    shutdown(write).await;
                    return CloseCause::new(CloseKind::LocalClose);
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
                tokio::select! {
                    biased;
                    () = overfull.wait() => {
                        outbound.release(n);
                        shutdown(write).await;
                        return CloseCause::new(CloseKind::SendQueueFull);
                    }
                    result = write.write_all(&wire) => {
                        outbound.release(n);
                        if result.is_err() {
                            shutdown(write).await;
                            return CloseCause::new(CloseKind::IoError);
                        }
                    }
                }
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
    mut decode: F,
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
        let n = tokio::select! {
            biased;
            () = overfull.wait() => return CloseCause::new(CloseKind::SendQueueFull),
            result = read.read(&mut buf) => match result {
                Ok(0) => return CloseCause::new(CloseKind::PeerClosed),
                Ok(n) => n,
                Err(_) => return CloseCause::new(CloseKind::IoError),
            },
        };
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
    use crate::queue::{ByteQueue, Overfull};
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
        let overfull = Arc::new(Overfull::new());
        let trip = Arc::clone(&overfull);
        let queue = ByteQueue::new(8);
        queue.try_push(b"abcdefgh".to_vec()).expect("queue");
        let task = tokio::spawn(async move {
            let mut write = StuckWrite { entered: flag };
            write_capped(&mut write, &queue, &overfull, |plain| {
                Ok(std::borrow::Cow::Borrowed(plain))
            })
            .await
        });
        until_entered(&entered).await;
        trip.trip();
        let cause = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("writer finished")
            .expect("joined");
        assert_eq!(cause.kind(), CloseKind::SendQueueFull);
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
            read_capped(&mut read, inbound, &overfull, |chunk| {
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
