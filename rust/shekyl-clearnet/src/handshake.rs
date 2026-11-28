// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clearnet handshake.
//!
//! The responder and the initiator share one budgeted write. The spans
//! (`queue_ns`, `compute_ns`, `write_ns`) are tracing fields at the site
//! that measured them.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_capped_stream::{node_gate, read_granted, write_granted, ReadStop};
use shekyl_p2p_transport::{
    prefix_for, Established, Initiator, InitiatorFlight, Responder, SendHalf, MESSAGE1_LEN,
    MESSAGE2_LEN, PREFIX_LEN,
};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick, WakeWait};
use shekyl_transport_layer::{LinkDirection, MessageClass};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::seam::SeamRecv;
use crate::stamping::Observed;
use crate::HandshakeTally;

/// A measured span, in nanoseconds. One field on the line that owns the
/// wait; nothing here changes what the connection does.
pub(crate) fn span_ns(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// How long a responder's handshake sat in the blocking queue, and how
/// long the pool then spent computing it.
struct PoolSpans {
    queue_ns: u64,
    compute_ns: u64,
}

pub(crate) enum Setup {
    Native,
    Noise { flight: Vec<u8>, send: SendHalf },
}

pub(crate) async fn noise_handshake<C>(
    read: &mut OwnedReadHalf,
    engine: &Handle<C>,
    network_id: &shekyl_p2p_transport::NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    setup: &mut Option<tokio::sync::oneshot::Sender<Setup>>,
    conn: u64,
) -> Result<SeamRecv, Observed>
where
    C: Clock + Clone + Send + 'static,
{
    let owner = engine
        .register(OwnerClass::Transport)
        .map_err(|_| Observed::HandshakeOwnFailure)?;
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(handshake_within.get()));
    owner
        .arm(deadline)
        .map_err(|_| Observed::HandshakeOwnFailure)?;
    tracing::debug!(
        conn,
        owner = ?owner.id(),
        armed_at = now.get(),
        deadline = deadline.get(),
        "clearnet handshake armed"
    );
    let fired = Arc::new(AtomicBool::new(false));
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let mut prefix = [0u8; PREFIX_LEN];
    if let Err(kind) = read_or_wake(read, &mut prefix, &mut wake, &fired, conn).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if prefix != prefix_for(network_id) {
        ignore(owner.deregister());
        return Err(Observed::PrefixMismatch);
    }
    let mut message1 = vec![0u8; MESSAGE1_LEN];
    if let Err(kind) = read_or_wake(read, &mut message1, &mut wake, &fired, conn).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if fired.load(Ordering::Acquire) {
        tally.skip();
        ignore(owner.deregister());
        return Err(Observed::HandshakeDeadline);
    }
    tally.queue();
    let queued = Instant::now();
    let tally_job = Arc::clone(tally);
    let network_id = *network_id;
    let fired_job = Arc::clone(&fired);
    let join = tokio::task::spawn_blocking(move || {
        handshake_job(&message1, network_id, &fired_job, &tally_job, queued)
    });
    tokio::pin!(join);
    let job = loop {
        tokio::select! {
            biased;
            result = wake.as_mut(), if !fired.load(Ordering::Acquire) => {
                fired.store(true, Ordering::Release);
                match result {
                    Ok(_) | Err(_) => {}
                }
            }
            result = &mut join => break result,
        }
    };
    ignore(owner.deregister());
    let (send, recv, flight, spans) = match job {
        Ok(Ok(done)) if !fired.load(Ordering::Acquire) => done,
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => return Err(Observed::HandshakeDeadline),
        Ok(Err(SkipOrFail::Unverified)) => return Err(Observed::HandshakeUnverified),
        Ok(Err(SkipOrFail::Own)) | Err(_) => return Err(Observed::HandshakeOwnFailure),
    };
    tracing::info!(
        conn,
        queue_ns = spans.queue_ns,
        compute_ns = spans.compute_ns,
        "clearnet responder handshake computed"
    );
    let Some(setup) = setup.take() else {
        return Err(Observed::OwnFailure);
    };
    if setup.send(Setup::Noise { flight, send }).is_err() {
        return Err(Observed::OwnFailure);
    }
    Ok(recv)
}

pub(crate) async fn initiator_handshake<C>(
    read: &mut OwnedReadHalf,
    mut write: OwnedWriteHalf,
    engine: &Handle<C>,
    network_id: &shekyl_p2p_transport::NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    conn: u64,
) -> Result<(OwnedWriteHalf, SendHalf, SeamRecv), Observed>
where
    C: Clock + Clone + Send + 'static,
{
    let owner = engine
        .register(OwnerClass::Transport)
        .map_err(|_| Observed::HandshakeOwnFailure)?;
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(handshake_within.get()));
    owner
        .arm(deadline)
        .map_err(|_| Observed::HandshakeOwnFailure)?;
    tracing::debug!(
        conn,
        owner = ?owner.id(),
        armed_at = now.get(),
        deadline = deadline.get(),
        "clearnet handshake armed"
    );
    let fired = Arc::new(AtomicBool::new(false));
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    tally.queue();
    let tally_job = Arc::clone(tally);
    let network_id = *network_id;
    let fired_job = Arc::clone(&fired);
    let queued = Instant::now();
    let join = tokio::task::spawn_blocking(move || {
        initiator_job(network_id, &fired_job, &tally_job, queued)
    });
    let job = await_job(join, &mut wake, &fired).await;
    let (initiator, flight, spans) = match job {
        Ok(Ok(done)) if !fired.load(Ordering::Acquire) => done,
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => {
            ignore(owner.deregister());
            drop(write.shutdown().await);
            return Err(Observed::HandshakeDeadline);
        }
        Ok(Err(SkipOrFail::Unverified | SkipOrFail::Own)) => {
            ignore(owner.deregister());
            drop(write.shutdown().await);
            return Err(Observed::HandshakeOwnFailure);
        }
        Err(_) => {
            ignore(owner.deregister());
            tally.dequeue();
            drop(write.shutdown().await);
            return Err(Observed::HandshakeOwnFailure);
        }
    };
    let writing = Instant::now();
    let wrote = tokio::select! {
        biased;
        result = wake.as_mut() => {
            fired.store(true, Ordering::Release);
            match result {
                Ok(_) | Err(_) => {}
            }
            node_gate().leave(LinkDirection::Up, conn);
            false
        }
        result = write_budgeted(&mut write, conn, flight.as_bytes()) => result,
    };
    if !wrote {
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(if fired.load(Ordering::Acquire) {
            Observed::HandshakeDeadline
        } else {
            Observed::HandshakeBroken
        });
    }
    tracing::info!(
        conn,
        queue_ns = spans.queue_ns,
        compute_ns = spans.compute_ns,
        write_ns = span_ns(writing.elapsed()),
        "clearnet initiator message1 sent"
    );
    let mut prefix = [0u8; PREFIX_LEN];
    if let Err(kind) = read_or_wake(read, &mut prefix, &mut wake, &fired, conn).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(kind);
    }
    if prefix != prefix_for(&network_id) {
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(Observed::PrefixMismatch);
    }
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    if let Err(kind) = read_or_wake(read, &mut message2, &mut wake, &fired, conn).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(kind);
    }
    if fired.load(Ordering::Acquire) {
        tally.skip();
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(Observed::HandshakeDeadline);
    }
    tally.queue();
    let tally_job = Arc::clone(tally);
    let fired_job = Arc::clone(&fired);
    let join = tokio::task::spawn_blocking(move || {
        finish_initiator(initiator, &message2, &fired_job, &tally_job)
    });
    let job = await_job(join, &mut wake, &fired).await;
    ignore(owner.deregister());
    let (send, recv) = match job {
        Ok(Ok(done)) if !fired.load(Ordering::Acquire) => done,
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => {
            drop(write.shutdown().await);
            return Err(Observed::HandshakeDeadline);
        }
        Ok(Err(SkipOrFail::Unverified)) => {
            drop(write.shutdown().await);
            return Err(Observed::HandshakeUnverified);
        }
        Ok(Err(SkipOrFail::Own)) | Err(_) => {
            drop(write.shutdown().await);
            return Err(Observed::HandshakeOwnFailure);
        }
    };
    Ok((write, send, recv))
}

/// Write `bytes` under the up budget.
///
/// The grant is held across the socket write. Drop, including when the
/// deadline select drops this call, returns what the socket did not take.
pub(crate) async fn write_budgeted(write: &mut OwnedWriteHalf, conn: u64, bytes: &[u8]) -> bool {
    write_granted(write, bytes, &node_gate(), conn, MessageClass::Session).await
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

fn note_skip(tally: &HandshakeTally, observed: Observed) {
    if observed == Observed::HandshakeDeadline {
        tally.skip();
    }
}

/// Why a handshake job did not finish: the deadline had already fired, the
/// peer's message did not verify, or this node's own step failed.
enum SkipOrFail {
    Skipped,
    Unverified,
    Own,
}

fn handshake_job(
    message1: &[u8],
    network_id: shekyl_p2p_transport::NetworkId,
    fired: &AtomicBool,
    tally: &HandshakeTally,
    queued: Instant,
) -> Result<(SendHalf, SeamRecv, Vec<u8>, PoolSpans), SkipOrFail> {
    let queue_ns = span_ns(queued.elapsed());
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    let computing = Instant::now();
    let result = (|| {
        let ready = Responder::new(&network_id)
            .read_message1(message1)
            .map_err(|_| SkipOrFail::Unverified)?;
        let (established, flight) = ready.write_message2().map_err(|_| SkipOrFail::Own)?;
        Ok((established, flight))
    })();
    tally.dequeue();
    let (established, flight) = result?;
    tally.compute();
    let compute_ns = span_ns(computing.elapsed());
    let (send, recv) = established_halves(established);
    let flight = flight.as_bytes().to_vec();
    Ok((
        send,
        SeamRecv::Noise {
            recv,
            pending: Vec::new(),
        },
        flight,
        PoolSpans {
            queue_ns,
            compute_ns,
        },
    ))
}

fn established_halves<const INITIATOR: bool>(
    established: Established<INITIATOR>,
) -> (SendHalf, shekyl_p2p_transport::RecvHalf) {
    established.split()
}

fn initiator_job(
    network_id: shekyl_p2p_transport::NetworkId,
    fired: &AtomicBool,
    tally: &HandshakeTally,
    queued: Instant,
) -> Result<(Initiator, InitiatorFlight, PoolSpans), SkipOrFail> {
    let queue_ns = span_ns(queued.elapsed());
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    let computing = Instant::now();
    match Initiator::new(&network_id) {
        Ok((initiator, flight)) => {
            tally.dequeue();
            Ok((
                initiator,
                flight,
                PoolSpans {
                    queue_ns,
                    compute_ns: span_ns(computing.elapsed()),
                },
            ))
        }
        Err(_) => {
            tally.dequeue();
            Err(SkipOrFail::Own)
        }
    }
}

fn finish_initiator(
    initiator: Initiator,
    message2: &[u8],
    fired: &AtomicBool,
    tally: &HandshakeTally,
) -> Result<(SendHalf, SeamRecv), SkipOrFail> {
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    let established = initiator
        .read_message2(message2)
        .map_err(|_| SkipOrFail::Unverified);
    tally.dequeue();
    let established = established?;
    tally.compute();
    let (send, recv) = established_halves(established);
    Ok((
        send,
        SeamRecv::Noise {
            recv,
            pending: Vec::new(),
        },
    ))
}

async fn await_job<T, C: Clock>(
    join: tokio::task::JoinHandle<T>,
    wake: &mut Pin<&mut WakeWait<'_, C>>,
    fired: &AtomicBool,
) -> Result<T, tokio::task::JoinError> {
    tokio::pin!(join);
    loop {
        tokio::select! {
            biased;
            result = wake.as_mut(), if !fired.load(Ordering::Acquire) => {
                fired.store(true, Ordering::Release);
                match result {
                    Ok(_) | Err(_) => {}
                }
            }
            result = &mut join => return result,
        }
    }
}

/// Read `buf` under the down budget, unless `wake` fires first.
///
/// A short socket read is a failure here: the handshake asked for the
/// whole buffer. The read is the shared one: nothing is held while the
/// peer is quiet, and the grant is settled before this returns the bytes.
async fn read_or_wake<C: Clock>(
    read: &mut OwnedReadHalf,
    buf: &mut [u8],
    wake: &mut Pin<&mut WakeWait<'_, C>>,
    fired: &AtomicBool,
    conn: u64,
) -> Result<(), Observed> {
    let gate = node_gate();
    let mut filled = 0usize;
    while filled < buf.len() {
        match read_granted(
            read,
            &mut buf[filled..],
            &gate,
            conn,
            MessageClass::Session,
            wake,
        )
        .await
        {
            Ok(n) => filled += n,
            Err(ReadStop::Cancel(_)) => {
                fired.store(true, Ordering::Release);
                gate.leave(LinkDirection::Down, conn);
                return Err(Observed::HandshakeDeadline);
            }
            Err(ReadStop::Eof | ReadStop::Failed) => return Err(Observed::HandshakeBroken),
        }
    }
    gate.record_message(LinkDirection::Down, conn);
    Ok(())
}
