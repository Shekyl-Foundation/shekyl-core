// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Refused accepts held half-closed until their first flight arrives
//! (`P2P_TRANSPORT_LAYER.md` D10.2; Rick, 2026-10-30).
//!
//! A Noise initiator writes its first flight as soon as it connects, so on
//! the internet that flight usually arrives after an accept-time refusal
//! has already closed the socket, and Linux answers bytes at a closed
//! socket with RST. A refused socket therefore stays half-closed: the FIN
//! goes at once, and the socket keeps reading until one initiator flight
//! has arrived and been dropped, or until the connector's handshake span
//! passes. Only then is it closed, with nothing unread, so the far side
//! sees FIN and no RST.
//!
//! One task holds every lingering socket of an accept loop, and one owner
//! on the timing engine carries the earliest deadline. Every socket
//! lingers for the same span, so the earliest is always the oldest. How
//! many may linger at once is capped by what the connector admits in one
//! span ([`Sockets::clearnet_linger_cap`]); a refusal beyond the cap closes
//! at once and leaves the RST residual D10.2 states.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use shekyl_p2p_transport::INITIATOR_FLIGHT_LEN;
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::drive::{close_before_channel, drain_initiator_flight};

/// The way into an accept loop's linger task. Clones share the task and
/// the count.
#[derive(Clone)]
pub struct Linger {
    tx: mpsc::UnboundedSender<TcpStream>,
    held: Arc<AtomicUsize>,
    cap: usize,
}

impl Linger {
    /// Start the linger task for one accept loop. `cap` is how many may
    /// linger at once; `span` is how long one may.
    pub fn spawn<C>(engine: Handle<C>, cap: usize, span: Tick) -> Self
    where
        C: Clock + Clone + Send + Sync + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let held = Arc::new(AtomicUsize::new(0));
        if cap > 0 {
            tokio::spawn(run(rx, engine, span, Arc::clone(&held)));
        }
        Self { tx, held, cap }
    }

    /// Close a refused socket the D10.2 way: half-closed until its first
    /// flight arrives or the span passes, or at once when the cap is
    /// reached.
    pub async fn close(&self, stream: TcpStream) {
        if !self.take_slot() {
            close_before_channel(stream).await;
            return;
        }
        if let Err(returned) = self.tx.send(stream) {
            self.held.fetch_sub(1, Ordering::AcqRel);
            close_before_channel(returned.0).await;
        }
    }

    /// Sockets lingering now.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    fn take_slot(&self) -> bool {
        self.held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < self.cap).then_some(held + 1)
            })
            .is_ok()
    }
}

/// One refused socket, half-closed.
struct Lingering {
    socket: TcpStream,
    until: Tick,
    /// Bytes of one initiator flight not yet read.
    left: usize,
}

async fn run<C>(
    mut rx: mpsc::UnboundedReceiver<TcpStream>,
    engine: Handle<C>,
    span: Tick,
    held: Arc<AtomicUsize>,
) where
    C: Clock + Clone + Send + Sync + 'static,
{
    let mut set: VecDeque<Lingering> = VecDeque::new();
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        // No engine: nothing can carry a deadline, so nothing lingers.
        rx.close();
        while let Some(stream) = rx.recv().await {
            held.fetch_sub(1, Ordering::AcqRel);
            close_before_channel(stream).await;
        }
        return;
    };
    loop {
        if let Some(front) = set.front() {
            if owner.arm(front.until).is_err() {
                break;
            }
        }
        tokio::select! {
            biased;
            arrived = rx.recv() => {
                let Some(mut socket) = arrived else { break };
                drop(socket.shutdown().await);
                let until = Tick::new(owner.clock().now().get().saturating_add(span.get()));
                set.push_back(Lingering { socket, until, left: INITIATOR_FLIGHT_LEN });
            }
            woke = owner.wait_wake_async(), if !set.is_empty() => {
                if woke.is_err() {
                    break;
                }
                let now = owner.clock().now();
                while set.front().is_some_and(|front| front.until <= now) {
                    if let Some(due) = set.pop_front() {
                        finish(due, &held);
                    }
                }
            }
            () = poll_fn(|cx| drain_ready(&mut set, &held, cx)), if !set.is_empty() => {}
        }
    }
    for lingering in set.drain(..) {
        finish(lingering, &held);
    }
    rx.close();
    while let Some(stream) = rx.recv().await {
        held.fetch_sub(1, Ordering::AcqRel);
        close_before_channel(stream).await;
    }
}

/// Read what has arrived on every lingering socket, and close each one
/// whose flight is in, whose peer has closed, or that has failed. Ready
/// when at least one closed.
fn drain_ready(
    set: &mut VecDeque<Lingering>,
    held: &AtomicUsize,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let before = set.len();
    let mut kept = VecDeque::with_capacity(before);
    while let Some(mut lingering) = set.pop_front() {
        if read_flight(&mut lingering, cx) {
            finish(lingering, held);
        } else {
            kept.push_back(lingering);
        }
    }
    *set = kept;
    if set.len() < before {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

/// `true` when this socket is done lingering. Leaves the task's waker on
/// the socket when it is not.
fn read_flight(lingering: &mut Lingering, cx: &mut Context<'_>) -> bool {
    let mut flight = [0u8; INITIATOR_FLIGHT_LEN];
    loop {
        match lingering.socket.poll_read_ready(cx) {
            Poll::Pending => return false,
            Poll::Ready(Err(_)) => return true,
            Poll::Ready(Ok(())) => {}
        }
        match lingering.socket.try_read(&mut flight[..lingering.left]) {
            Ok(0) => return true,
            Ok(read) => {
                lingering.left = lingering.left.saturating_sub(read);
                if lingering.left == 0 {
                    return true;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return true,
        }
    }
}

/// Drop what is left unread, without waiting, then close.
///
/// The reads go to the kernel directly ([`drain_initiator_flight`]):
/// tokio's `try_read` answers from its cached readiness and could leave
/// bytes queued, which the close would answer with RST.
fn finish(lingering: Lingering, held: &AtomicUsize) {
    if let Ok(socket) = lingering.socket.into_std() {
        drain_initiator_flight(socket, lingering.left);
    }
    held.fetch_sub(1, Ordering::AcqRel);
}
