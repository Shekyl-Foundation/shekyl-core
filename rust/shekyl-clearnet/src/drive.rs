// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One accepted socket. The write half has one task. The handshake
//! deadline is armed at accept, before any read, so time in the
//! blocking queue counts.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_p2p_transport::{
    prefix_for, Established, NetworkId, Responder, SendHalf, MESSAGE1_LEN, PREFIX_LEN,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::{Clock, Handle, OwnerClass, OwnerHandle, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, CloseResult, OpenError, Sockets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::inode::socket_descriptors;
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
}

struct Outbound {
    tx: mpsc::Sender<Vec<u8>>,
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
    mut stream: TcpStream,
    engine: Handle<C>,
    kind: ChannelChoice,
    network_id: NetworkId,
    handshake_within: Tick,
    tally: Arc<HandshakeTally>,
    sessions: mpsc::UnboundedSender<Session>,
    _peer: SocketAddr,
) -> CloseCause
where
    C: Clock + Clone + Send + 'static,
{
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&stream);
    if socket_descriptors(fd).ok() != Some(1) {
        drop(stream.shutdown().await);
        return CloseCause::new(CloseKind::TransportHandshakeFailed);
    }
    let (mut read, write) = stream.into_split();
    if socket_descriptors(fd).ok() != Some(1) {
        drop(write);
        return CloseCause::new(CloseKind::TransportHandshakeFailed);
    }
    let overfull = Arc::new(crate::Overfull::new());
    let (out_tx, out_rx) = mpsc::channel(1);
    let outbound = Outbound { tx: out_tx };
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
    mut outbound: mpsc::Receiver<Vec<u8>>,
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
                let Some(plain) = next else {
                    drop(write.shutdown().await);
                    return None;
                };
                let Ok(wire) = seam.encode(&plain) else {
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
            if inbound.try_send(piece).is_err() {
                overfull.trip();
                return CloseCause::new(CloseKind::SendQueueFull);
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
    let clock = owner.clock().clone();
    let mut prefix = [0u8; PREFIX_LEN];
    if let Err(kind) = read_or_due(read, &mut prefix, &clock, deadline, &fired).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if prefix != prefix_for(network_id) {
        ignore(owner.deregister());
        return Err(CloseKind::PrefixMismatch);
    }
    let mut message1 = vec![0u8; MESSAGE1_LEN];
    if let Err(kind) = read_or_due(read, &mut message1, &clock, deadline, &fired).await {
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
    let tally = Arc::clone(tally);
    let network_id = *network_id;
    let fired_job = Arc::clone(&fired);
    let join = tokio::task::spawn_blocking(move || {
        handshake_job(owner, &message1, network_id, &fired_job, &tally)
    });
    tokio::pin!(join);
    let mut watch = std::pin::pin!(until_due(clock, deadline, Arc::clone(&fired)));
    let job = loop {
        tokio::select! {
            () = &mut watch => {}
            result = &mut join => break result,
        }
    };
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

#[allow(clippy::needless_pass_by_value)] // the blocking job owns the owner and drops it here
fn handshake_job(
    owner: OwnerHandle<impl Clock>,
    message1: &[u8],
    network_id: NetworkId,
    fired: &AtomicBool,
    tally: &HandshakeTally,
) -> Result<(SendHalf, SeamRecv, Vec<u8>), SkipOrFail> {
    let due = fired.load(Ordering::Acquire) || deadline_already_fired(&owner);
    if due {
        tally.skip();
        tally.dequeue();
        ignore(owner.deregister());
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
    ignore(owner.deregister());
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

fn deadline_already_fired(owner: &OwnerHandle<impl Clock>) -> bool {
    match owner.poll_wake() {
        Ok(Some(_)) | Err(_) => true,
        Ok(None) => false,
    }
}

async fn read_or_due<C: Clock + Clone>(
    read: &mut OwnedReadHalf,
    buf: &mut [u8],
    clock: &C,
    deadline: Tick,
    fired: &Arc<AtomicBool>,
) -> Result<(), CloseKind> {
    let clock = clock.clone();
    tokio::select! {
        biased;
        () = until_due(clock, deadline, Arc::clone(fired)) => {
            Err(CloseKind::TransportTimeout)
        }
        result = read.read_exact(buf) => {
            result
                .map(|_| ())
                .map_err(|_| CloseKind::TransportHandshakeFailed)
        }
    }
}

async fn until_due<C: Clock>(clock: C, deadline: Tick, fired: Arc<AtomicBool>) {
    loop {
        if fired.load(Ordering::Acquire) {
            return;
        }
        match clock.wait_for(deadline) {
            Some(Duration::ZERO) => {
                fired.store(true, Ordering::Release);
                return;
            }
            Some(wait) => tokio::time::sleep(wait).await,
            None => tokio::task::yield_now().await,
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
