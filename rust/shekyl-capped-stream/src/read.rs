// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One budgeted read, shared by the session copy and the handshake.
//!
//! The wait for the peer holds nothing. The grant is taken only once the
//! socket is readable, and drop returns every byte the socket did not take.
//! A rate of zero waits inside the grant.

use std::future::Future;
use std::io::{ErrorKind, Result as IoResult};

use shekyl_transport_layer::{LinkDirection, MessageClass};
use tokio::net::tcp::OwnedReadHalf;

use crate::gate::{HeldGrant, LinkGate};

/// A socket read that separates "bytes are waiting" from taking them.
///
/// [`ReadyRead::wait_readable`] completes when a later [`ReadyRead::try_read`]
/// can return without waiting. `try_read` returns [`ErrorKind::WouldBlock`]
/// when that readiness was stale. It does not wait: the caller waits again,
/// and the grant it held for the stale read has already been dropped.
pub trait ReadyRead {
    fn wait_readable(&mut self) -> impl Future<Output = IoResult<()>> + '_;

    fn try_read(&mut self, buf: &mut [u8]) -> IoResult<usize>;
}

impl ReadyRead for OwnedReadHalf {
    fn wait_readable(&mut self) -> impl Future<Output = IoResult<()>> + '_ {
        self.readable()
    }

    fn try_read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // The inherent method. A `self.try_read` call here is this trait method.
        tcp_try_read(self, buf)
    }
}

fn tcp_try_read(read: &OwnedReadHalf, buf: &mut [u8]) -> IoResult<usize> {
    read.try_read(buf)
}

/// Why [`read_granted`] produced no bytes.
#[derive(Debug)]
pub enum ReadStop<C> {
    /// `cancel` completed with this value.
    Cancel(C),
    /// The peer closed the socket.
    Eof,
    /// The socket failed.
    Failed,
}

/// Read one slice into `buf` under the down budget.
///
/// Returns how many bytes landed. Those bytes are already charged: the
/// grant has been dropped, and the bucket holds only what the socket did
/// not take. `cancel` is polled while waiting for the peer and while
/// waiting for a grant. An empty `buf` reads nothing and charges nothing.
pub async fn read_granted<R, F, C>(
    read: &mut R,
    buf: &mut [u8],
    gate: &LinkGate,
    conn: u64,
    class: MessageClass,
    cancel: &mut F,
) -> Result<usize, ReadStop<C>>
where
    R: ReadyRead + Unpin,
    F: Future<Output = C> + Unpin,
{
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        tokio::select! {
            biased;
            value = &mut *cancel => return Err(ReadStop::Cancel(value)),
            ready = read.wait_readable() => {
                if ready.is_err() {
                    return Err(ReadStop::Failed);
                }
            }
        }
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        tokio::select! {
            biased;
            value = &mut *cancel => return Err(ReadStop::Cancel(value)),
            grant = HeldGrant::acquire(gate, LinkDirection::Down, conn, class, want) => {
                match consume(read, buf, grant) {
                    Consume::Bytes(n) => return Ok(n),
                    Consume::Stale => continue,
                    Consume::Eof => return Err(ReadStop::Eof),
                    Consume::Failed => return Err(ReadStop::Failed),
                }
            }
        }
    }
}

enum Consume {
    Bytes(usize),
    Stale,
    Eof,
    Failed,
}

/// Take what the socket has of this grant. The grant drops here, so a
/// short read and a stale readiness both return the untaken tokens.
fn consume<R: ReadyRead>(read: &mut R, buf: &mut [u8], mut grant: HeldGrant) -> Consume {
    let room = grant.room(buf.len());
    if room == 0 {
        return Consume::Stale;
    }
    loop {
        match read.try_read(&mut buf[..room]) {
            Ok(0) => return Consume::Eof,
            Ok(n) => {
                let moved = u64::try_from(n).unwrap_or(0);
                grant.accept(moved);
                return Consume::Bytes(n);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Consume::Stale,
            Err(_) => return Consume::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::pending;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::Waker;

    use shekyl_transport_layer::{LinkDirection, MessageClass};

    use super::{read_granted, ReadStop, ReadyRead};
    use crate::gate::LinkGate;

    struct Pipe {
        incoming: VecDeque<u8>,
        waker: Option<Waker>,
        /// The next readiness is a lie: nothing is buffered.
        stale_once: bool,
        ready: Arc<AtomicBool>,
        tried: Arc<AtomicBool>,
    }

    impl Pipe {
        fn with_bytes(bytes: &[u8]) -> Self {
            Self {
                incoming: VecDeque::from(bytes.to_vec()),
                waker: None,
                stale_once: false,
                ready: Arc::new(AtomicBool::new(false)),
                tried: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl ReadyRead for Pipe {
        fn wait_readable(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> + '_ {
            std::future::poll_fn(|cx| {
                if self.stale_once || !self.incoming.is_empty() {
                    self.stale_once = false;
                    self.ready.store(true, Ordering::Release);
                    return std::task::Poll::Ready(Ok(()));
                }
                self.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            })
        }

        fn try_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.tried.store(true, Ordering::Release);
            if self.incoming.is_empty() {
                return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
            }
            let n = buf.len().min(self.incoming.len());
            for slot in &mut buf[..n] {
                *slot = self.incoming.pop_front().expect("byte");
            }
            Ok(n)
        }
    }

    fn freeze(gate: &LinkGate) {
        gate.install_clock(Arc::new(|| 0));
    }

    async fn until(flag: &AtomicBool) {
        let start = std::time::Instant::now();
        while !flag.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(2),
                "socket call"
            );
            tokio::task::yield_now().await;
        }
    }

    /// The bytes are charged before `read_granted` returns, and only the
    /// bytes that landed: the rest of the bucket is free for someone else.
    #[tokio::test]
    async fn a_read_is_charged_before_it_returns() {
        const RATE: u64 = 8;
        let gate = LinkGate::new();
        freeze(&gate);
        gate.set_down(Some(RATE));
        let mut pipe = Pipe::with_bytes(&[1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        let mut cancel = pending::<()>();
        let n = read_granted(
            &mut pipe,
            &mut buf,
            &gate,
            1,
            MessageClass::Session,
            &mut cancel,
        )
        .await
        .expect("read");
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);
        assert_eq!(gate.connection(1).bytes_down, 4);
        let rest = gate
            .acquire(LinkDirection::Down, 2, MessageClass::Session, RATE)
            .await;
        assert_eq!(rest, RATE - 4);
    }

    /// Readiness that produces no byte returns the whole grant. The reader
    /// is waiting again, and another connection can take the bucket.
    #[tokio::test]
    async fn stale_readiness_returns_the_grant() {
        const RATE: u64 = 32;
        let gate = LinkGate::new();
        freeze(&gate);
        gate.set_down(Some(RATE));
        let tried = Arc::new(AtomicBool::new(false));
        let mut pipe = Pipe {
            incoming: VecDeque::new(),
            waker: None,
            stale_once: true,
            ready: Arc::new(AtomicBool::new(false)),
            tried: Arc::clone(&tried),
        };
        let mut buf = [0u8; 32];
        let mut cancel = pending::<()>();
        let gate_read = gate.clone();
        let task = tokio::spawn(async move {
            read_granted(
                &mut pipe,
                &mut buf,
                &gate_read,
                1,
                MessageClass::Session,
                &mut cancel,
            )
            .await
        });
        until(&tried).await;
        let other = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            gate.acquire(LinkDirection::Down, 2, MessageClass::Session, RATE),
        )
        .await
        .expect("the stale read still holds the bucket");
        assert_eq!(other, RATE);
        assert_eq!(gate.connection(1).bytes_down, 0);
        task.abort();
    }

    #[tokio::test]
    async fn a_rate_of_zero_reads_nothing_until_the_rate_changes() {
        let gate = LinkGate::new();
        freeze(&gate);
        gate.set_down(Some(0));
        let ready = Arc::new(AtomicBool::new(false));
        let tried = Arc::new(AtomicBool::new(false));
        let mut pipe = Pipe::with_bytes(&[9, 9, 9, 9]);
        pipe.ready = Arc::clone(&ready);
        pipe.tried = Arc::clone(&tried);
        let mut buf = [0u8; 4];
        let mut cancel = pending::<()>();
        let gate_read = gate.clone();
        let task = tokio::spawn(async move {
            read_granted(
                &mut pipe,
                &mut buf,
                &gate_read,
                1,
                MessageClass::Session,
                &mut cancel,
            )
            .await
        });
        // The socket is readable. At rate zero the grant waits before
        // `try_read`, so the socket still holds every byte.
        until(&ready).await;
        assert!(
            !tried.load(Ordering::Acquire),
            "a zero rate read the socket"
        );
        assert_eq!(gate.connection(1).bytes_down, 0);
        gate.set_down(Some(4));
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("the read finished")
            .expect("joined")
            .expect("bytes");
        assert_eq!(n, 4);
        assert_eq!(gate.connection(1).bytes_down, 4);
    }

    #[tokio::test]
    async fn cancelling_while_the_peer_is_quiet_holds_no_tokens() {
        const RATE: u64 = 64;
        let gate = LinkGate::new();
        freeze(&gate);
        gate.set_down(Some(RATE));
        let mut pipe = Pipe::with_bytes(&[]);
        let mut buf = [0u8; 64];
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let gate_read = gate.clone();
        let task = tokio::spawn(async move {
            let mut cancel = std::pin::pin!(async { rx.await.ok() });
            read_granted(
                &mut pipe,
                &mut buf,
                &gate_read,
                1,
                MessageClass::Session,
                &mut cancel,
            )
            .await
        });
        tokio::task::yield_now().await;
        tx.send(()).expect("cancel");
        let stopped = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("the read finished")
            .expect("joined");
        assert!(matches!(stopped, Err(ReadStop::Cancel(Some(())))));
        assert_eq!(gate.connection(1).bytes_down, 0);
        let granted = gate
            .acquire(LinkDirection::Down, 2, MessageClass::Session, RATE)
            .await;
        assert_eq!(granted, RATE);
    }
}
