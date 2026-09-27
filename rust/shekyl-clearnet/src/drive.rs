// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One accepted socket. The write half has one task. The handshake
//! deadline is armed at accept, before any read, so time in the
//! blocking queue counts.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use shekyl_p2p_transport::{
    prefix_for, Established, NetworkId, Responder, SendHalf, MESSAGE1_LEN, PREFIX_LEN,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick, WakeWait};
use shekyl_transport_layer::{CloseCause, CloseKind, CloseResult, OpenError, Sockets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::seam::{SeamRecv, SeamSend};
use crate::{ChannelChoice, HandshakeTally, Session};

pub struct Accept {
    pub stream: TcpStream,
    pub sockets: Sockets,
    pub ceiling: InboundCeiling,
    pub kind: ChannelChoice,
    pub network_id: NetworkId,
    pub handshake_within: Tick,
    pub tally: Arc<HandshakeTally>,
    pub sessions: mpsc::UnboundedSender<Session>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
}

struct Outbound {
    tx: mpsc::UnboundedSender<Queued>,
    queue: SendQueue,
}

pub async fn accept_one<C>(accept: Accept, engine: Handle<C>)
where
    C: Clock + Clone + Send + 'static,
{
    let Accept {
        mut stream,
        sockets,
        ceiling,
        kind,
        network_id,
        handshake_within,
        tally,
        sessions,
        on_cause,
        send_queue_bytes,
    } = accept;
    let Ok(peer) = stream.peer_addr() else {
        finish_before_channel(&mut stream, &on_cause, CloseKind::TransportHandshakeFailed).await;
        return;
    };
    let now = engine.clock().now();
    let reserved = match sockets.accept_clearnet(peer.ip(), ceiling, now) {
        Ok(open) => open,
        Err(OpenError::Refused(cause)) => {
            drop(stream.shutdown().await);
            on_cause(cause);
            return;
        }
        Err(OpenError::Exhausted) => {
            finish_before_channel(&mut stream, &on_cause, CloseKind::AdmissionRefused).await;
            return;
        }
    };
    let cause = serve(
        stream,
        engine,
        kind,
        network_id,
        handshake_within,
        tally,
        sessions,
        send_queue_bytes,
        peer,
    )
    .await;
    match reserved.close(cause) {
        CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
    }
    on_cause(cause);
}

async fn finish_before_channel(
    stream: &mut TcpStream,
    on_cause: &Arc<dyn Fn(CloseCause) + Send + Sync>,
    kind: CloseKind,
) {
    drop(stream.shutdown().await);
    on_cause(CloseCause::new(kind));
}

#[allow(clippy::too_many_arguments)]
async fn serve<C>(
    stream: TcpStream,
    engine: Handle<C>,
    kind: ChannelChoice,
    network_id: NetworkId,
    handshake_within: Tick,
    tally: Arc<HandshakeTally>,
    sessions: mpsc::UnboundedSender<Session>,
    send_queue_bytes: usize,
    _peer: SocketAddr,
) -> CloseCause
where
    C: Clock + Clone + Send + 'static,
{
    let (mut read, write) = stream.into_split();
    let overfull = Arc::new(crate::Overfull::new());
    let queue = SendQueue::new(send_queue_bytes);
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let outbound = Outbound {
        tx: out_tx,
        queue: queue.clone(),
    };
    let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(write_half(write, setup_rx, out_rx, Arc::clone(&overfull)));
    let (inbound_tx, inbound_rx) = mpsc::channel(1);
    let mut setup_tx = Some(setup_tx);
    let opened = match kind {
        ChannelChoice::Plain => {
            if let Some(tx) = setup_tx.take() {
                drop(tx.send(Setup::Plain));
            }
            Ok(SeamRecv::Plain)
        }
        ChannelChoice::Noise => {
            noise_handshake(
                &mut read,
                &engine,
                &network_id,
                handshake_within,
                &tally,
                &mut setup_tx,
            )
            .await
        }
    };
    let recv = match opened {
        Ok(recv) => recv,
        Err(kind) => {
            drop(setup_tx);
            drop(outbound);
            drop(writer.await);
            return CloseCause::new(kind);
        }
    };
    let session = Session {
        inbound: inbound_rx,
        outbound: outbound.tx.clone(),
        queue: outbound.queue.clone(),
        overfull: Arc::clone(&overfull),
    };
    if sessions.send(session).is_err() {
        drop(outbound);
        drop(writer.await);
        return CloseCause::new(CloseKind::LocalClose);
    }
    let read_cause = read_half(read, recv, inbound_tx, Arc::clone(&overfull)).await;
    drop(outbound);
    let write_cause = writer.await.ok().flatten();
    write_cause.unwrap_or(read_cause)
}

enum Setup {
    Plain,
    Noise { flight: Vec<u8>, send: SendHalf },
}

async fn write_half(
    mut write: OwnedWriteHalf,
    setup: tokio::sync::oneshot::Receiver<Setup>,
    mut outbound: mpsc::UnboundedReceiver<Queued>,
    overfull: Arc<crate::Overfull>,
) -> Option<CloseCause> {
    let setup = setup.await.ok()?;
    let mut seam = match setup {
        Setup::Plain => SeamSend::Plain,
        Setup::Noise { flight, send } => {
            if write.write_all(&flight).await.is_err() {
                return Some(CloseCause::new(CloseKind::IoError));
            }
            SeamSend::Noise(send)
        }
    };
    loop {
        if overfull.tripped() {
            drop(write.shutdown().await);
            return Some(CloseCause::new(CloseKind::SendQueueFull));
        }
        tokio::select! {
            biased;
            () = overfull.wait() => {
                drop(write.shutdown().await);
                return Some(CloseCause::new(CloseKind::SendQueueFull));
            }
            next = outbound.recv() => {
                let Some(queued) = next else {
                    drop(write.shutdown().await);
                    return None;
                };
                let Ok(wire) = seam.encode(&queued.bytes) else {
                    drop(write.shutdown().await);
                    return Some(CloseCause::new(CloseKind::RecordRejected));
                };
                if !wire.is_empty() && write.write_all(&wire).await.is_err() {
                    return Some(CloseCause::new(CloseKind::IoError));
                }
            }
        }
    }
}

async fn read_half(
    mut read: OwnedReadHalf,
    mut seam: SeamRecv,
    inbound: mpsc::Sender<Vec<u8>>,
    overfull: Arc<crate::Overfull>,
) -> CloseCause {
    let mut buf = [0u8; 8192];
    loop {
        if overfull.tripped() {
            return CloseCause::new(CloseKind::SendQueueFull);
        }
        let n = match read.read(&mut buf).await {
            Ok(0) => return CloseCause::new(CloseKind::PeerClosed),
            Ok(n) => n,
            Err(_) => return CloseCause::new(CloseKind::IoError),
        };
        let Ok(pieces) = seam.push(&buf[..n]) else {
            return CloseCause::new(CloseKind::RecordRejected);
        };
        for piece in pieces {
            if inbound.send(piece).await.is_err() {
                return CloseCause::new(CloseKind::LocalClose);
            }
        }
    }
}

async fn noise_handshake<C>(
    read: &mut OwnedReadHalf,
    engine: &Handle<C>,
    network_id: &NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    setup: &mut Option<tokio::sync::oneshot::Sender<Setup>>,
) -> Result<SeamRecv, CloseKind>
where
    C: Clock + Clone + Send + 'static,
{
    let owner = engine
        .register(OwnerClass::Transport)
        .map_err(|_| CloseKind::TransportHandshakeFailed)?;
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(handshake_within.get()));
    owner
        .arm(deadline)
        .map_err(|_| CloseKind::TransportHandshakeFailed)?;
    let fired = Arc::new(AtomicBool::new(false));
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let mut prefix = [0u8; PREFIX_LEN];
    if let Err(kind) = read_or_wake(read, &mut prefix, &mut wake, &fired).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if prefix != prefix_for(network_id) {
        ignore(owner.deregister());
        return Err(CloseKind::PrefixMismatch);
    }
    let mut message1 = vec![0u8; MESSAGE1_LEN];
    if let Err(kind) = read_or_wake(read, &mut message1, &mut wake, &fired).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if fired.load(Ordering::Acquire) {
        tally.skip();
        ignore(owner.deregister());
        return Err(CloseKind::TransportTimeout);
    }
    tally.queue();
    let tally_job = Arc::clone(tally);
    let network_id = *network_id;
    let fired_job = Arc::clone(&fired);
    let join = tokio::task::spawn_blocking(move || {
        handshake_job(&message1, network_id, &fired_job, &tally_job)
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
    let (send, recv, flight) = match job {
        Ok(Ok(done)) => done,
        Ok(Err(SkipOrFail::Skipped)) => return Err(CloseKind::TransportTimeout),
        Ok(Err(SkipOrFail::Failed)) | Err(_) => {
            return Err(CloseKind::TransportHandshakeFailed);
        }
    };
    let Some(setup) = setup.take() else {
        return Err(CloseKind::LocalClose);
    };
    if setup.send(Setup::Noise { flight, send }).is_err() {
        return Err(CloseKind::LocalClose);
    }
    Ok(recv)
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

fn note_skip(tally: &HandshakeTally, kind: CloseKind) {
    if kind == CloseKind::TransportTimeout {
        tally.skip();
    }
}

enum SkipOrFail {
    Skipped,
    Failed,
}

fn handshake_job(
    message1: &[u8],
    network_id: NetworkId,
    fired: &AtomicBool,
    tally: &HandshakeTally,
) -> Result<(SendHalf, SeamRecv, Vec<u8>), SkipOrFail> {
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    let result = (|| {
        let ready = Responder::new(&network_id)
            .read_message1(message1)
            .map_err(|_| SkipOrFail::Failed)?;
        let (established, message2) = ready.write_message2().map_err(|_| SkipOrFail::Failed)?;
        Ok((established, message2))
    })();
    tally.dequeue();
    let (established, message2) = result?;
    tally.compute();
    let (send, recv) = established_halves(established);
    let mut flight = Vec::with_capacity(PREFIX_LEN + message2.len());
    flight.extend_from_slice(&prefix_for(&network_id));
    flight.extend_from_slice(&message2);
    Ok((
        send,
        SeamRecv::Noise {
            recv,
            pending: Vec::new(),
        },
        flight,
    ))
}

fn established_halves(
    established: Established<false>,
) -> (SendHalf, shekyl_p2p_transport::RecvHalf) {
    established.split()
}

async fn read_or_wake<C: Clock>(
    read: &mut OwnedReadHalf,
    buf: &mut [u8],
    wake: &mut Pin<&mut WakeWait<'_, C>>,
    fired: &AtomicBool,
) -> Result<(), CloseKind> {
    tokio::select! {
        biased;
        result = wake.as_mut() => {
            fired.store(true, Ordering::Release);
            match result {
                Ok(_) | Err(_) => {}
            }
            Err(CloseKind::TransportTimeout)
        }
        result = read.read_exact(buf) => {
            result
                .map(|_| ())
                .map_err(|_| CloseKind::TransportHandshakeFailed)
        }
    }
}

#[derive(Clone)]
pub(crate) struct SendQueue {
    queued: Arc<AtomicUsize>,
    limit: usize,
}

struct Permit {
    queued: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.queued.fetch_sub(self.bytes, Ordering::Release);
    }
}

pub(crate) struct Queued {
    bytes: Vec<u8>,
    _permit: Permit,
}

impl SendQueue {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            queued: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    /// Reserve `bytes.len()` against the byte cap. A buffer that does not
    /// fit is not queued.
    pub(crate) fn try_enqueue(&self, bytes: Vec<u8>) -> Result<Queued, ()> {
        let n = bytes.len();
        if n == 0 {
            return Ok(Queued {
                bytes,
                _permit: Permit {
                    queued: Arc::clone(&self.queued),
                    bytes: 0,
                },
            });
        }
        loop {
            let current = self.queued.load(Ordering::Acquire);
            let Some(next) = current.checked_add(n) else {
                return Err(());
            };
            if next > self.limit {
                return Err(());
            }
            if self
                .queued
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Queued {
                    bytes,
                    _permit: Permit {
                        queued: Arc::clone(&self.queued),
                        bytes: n,
                    },
                });
            }
        }
    }
}

impl HandshakeTally {
    pub(crate) fn queue(&self) {
        self.queued.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn dequeue(&self) {
        self.queued.fetch_sub(1, Ordering::Release);
    }

    pub(crate) fn compute(&self) {
        self.computed.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn skip(&self) {
        self.skipped.fetch_add(1, Ordering::Release);
    }
}

pub fn zero_tally() -> HandshakeTally {
    HandshakeTally {
        computed: AtomicU64::new(0),
        skipped: AtomicU64::new(0),
        queued: AtomicU64::new(0),
    }
}
