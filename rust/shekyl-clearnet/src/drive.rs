// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One accepted socket. The write half has one task. The handshake
//! deadline is armed at accept, before any read, so time in the
//! blocking queue counts.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use shekyl_capped_stream::{read_capped, write_capped, ByteQueue, Overfull, StreamEnds};
use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::{
    prefix_for, Established, Initiator, NetworkId, Responder, SendHalf, MESSAGE1_LEN, MESSAGE2_LEN,
    PREFIX_LEN,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick, WakeWait};
use shekyl_transport_layer::{
    check_dial, CloseCause, CloseKind, CloseResult, ConnectorId, OpenError, OpenSocket, Sockets,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::seam::{SeamRecv, SeamSend};
use crate::{ChannelChoice, HandshakeTally, Session};

pub(crate) enum Role {
    Responder,
    Initiator,
}

/// A channel the connector admitted, with the peer it was admitted for.
///
/// The zone host takes `open` into the seam. The connector does not close
/// that reservation. Absent this handoff, the connector keeps it until the
/// socket ends.
pub struct Admitted {
    pub open: OpenSocket,
    pub session: Session,
    pub ip: IpAddr,
    pub port: u16,
}

pub struct Dial {
    pub address: NetworkAddress,
    pub proxy: Option<SocketAddr>,
    pub sockets: Sockets,
    pub kind: ChannelChoice,
    pub network_id: NetworkId,
    pub handshake_within: Tick,
    pub tally: Arc<HandshakeTally>,
    pub sessions: mpsc::UnboundedSender<Session>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    pub handoff: Option<mpsc::UnboundedSender<Admitted>>,
}

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
    pub handoff: Option<mpsc::UnboundedSender<Admitted>>,
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
        handoff,
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
    let cause = if let Some(tx) = handoff {
        serve(
            stream,
            engine,
            kind,
            network_id,
            handshake_within,
            tally,
            sessions,
            send_queue_bytes,
            peer,
            Role::Responder,
            Some(reserved),
            Some(tx),
        )
        .await
    } else {
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
            Role::Responder,
            None,
            None,
        )
        .await;
        match reserved.close(cause) {
            CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
        }
        cause
    };
    on_cause(cause);
}

pub async fn dial_one<C>(dial: Dial, engine: Handle<C>)
where
    C: Clock + Clone + Send + 'static,
{
    let Dial {
        address,
        proxy,
        sockets,
        kind,
        network_id,
        handshake_within,
        tally,
        sessions,
        on_cause,
        send_queue_bytes,
        handoff,
    } = dial;
    if let Err(cause) = check_dial(ConnectorId::Clearnet, &address) {
        on_cause(cause);
        return;
    }
    let Some((ip, port)) = socket_of(&address) else {
        on_cause(CloseCause::new(CloseKind::DialFailed));
        return;
    };
    let dest = SocketAddr::new(ip, port);
    let target = proxy.unwrap_or(dest);
    let Ok(mut stream) = TcpStream::connect(target).await else {
        on_cause(CloseCause::new(CloseKind::DialFailed));
        return;
    };
    if proxy.is_some() {
        match socks_connect(&mut stream, Isolation::Principal, Destination::Ip(dest)).await {
            Ok(()) => {}
            Err(SocksError::Refused { reply }) => {
                drop(stream.shutdown().await);
                on_cause(CloseCause::proxy_refused(u16::from(reply)));
                return;
            }
            Err(
                SocksError::Io(_)
                | SocksError::Malformed
                | SocksError::AuthRejected { .. }
                | SocksError::AuthFailed { .. },
            ) => {
                drop(stream.shutdown().await);
                on_cause(CloseCause::new(CloseKind::DialFailed));
                return;
            }
        }
    }
    let now = engine.clock().now();
    let reserved = match sockets.open_clearnet(ip, now) {
        Ok(open) => open,
        Err(OpenError::Refused(cause)) => {
            drop(stream.shutdown().await);
            on_cause(cause);
            return;
        }
        Err(OpenError::Exhausted) => {
            finish_before_channel(&mut stream, &on_cause, CloseKind::DialFailed).await;
            return;
        }
    };
    let cause = if let Some(tx) = handoff {
        serve(
            stream,
            engine,
            kind,
            network_id,
            handshake_within,
            tally,
            sessions,
            send_queue_bytes,
            dest,
            Role::Initiator,
            Some(reserved),
            Some(tx),
        )
        .await
    } else {
        let cause = serve(
            stream,
            engine,
            kind,
            network_id,
            handshake_within,
            tally,
            sessions,
            send_queue_bytes,
            dest,
            Role::Initiator,
            None,
            None,
        )
        .await;
        match reserved.close(cause) {
            CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
        }
        cause
    };
    on_cause(cause);
}

fn socket_of(address: &NetworkAddress) -> Option<(IpAddr, u16)> {
    match address {
        NetworkAddress::Ipv4 { ip, port } => Some((IpAddr::V4(*ip), *port)),
        NetworkAddress::Ipv6 { ip, port } => Some((IpAddr::V6(*ip), *port)),
        NetworkAddress::Tor { .. } | NetworkAddress::I2p { .. } => None,
    }
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
    peer: SocketAddr,
    role: Role,
    mut reserved: Option<OpenSocket>,
    handoff: Option<mpsc::UnboundedSender<Admitted>>,
) -> CloseCause
where
    C: Clock + Clone + Send + 'static,
{
    let (mut read, write) = stream.into_split();
    let StreamEnds {
        session,
        writer_queue,
        hold,
        overfull,
        inbound,
    } = StreamEnds::open(send_queue_bytes);
    let opened = open_channel(
        kind,
        role,
        &mut read,
        write,
        &engine,
        &network_id,
        handshake_within,
        &tally,
        writer_queue,
        Arc::clone(&overfull),
    )
    .await;
    let (mut writer, recv) = match opened {
        Ok(pair) => pair,
        Err(kind) => {
            drop(hold);
            let cause = CloseCause::new(kind);
            if let Some(open) = reserved.take() {
                match open.close(cause) {
                    CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
                }
            }
            return cause;
        }
    };
    if let Some(tx) = handoff {
        let Some(open) = reserved.take() else {
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        };
        let admitted = Admitted {
            open,
            session,
            ip: peer.ip(),
            port: peer.port(),
        };
        if tx.send(admitted).is_err() {
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        }
    } else if sessions.send(session).is_err() {
        drop(hold);
        drop(writer.await);
        return CloseCause::new(CloseKind::LocalClose);
    }
    let read_fut = read_half(read, recv, inbound, Arc::clone(&overfull));
    tokio::pin!(read_fut);
    tokio::select! {
        read_cause = &mut read_fut => {
            drop(hold);
            writer.abort();
            drop(writer.await);
            read_cause
        }
        write_cause = &mut writer => {
            drop(hold);
            write_cause
                .ok()
                .flatten()
                .unwrap_or(CloseCause::new(CloseKind::LocalClose))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_channel<C>(
    kind: ChannelChoice,
    role: Role,
    read: &mut OwnedReadHalf,
    write: OwnedWriteHalf,
    engine: &Handle<C>,
    network_id: &NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    outbound: ByteQueue,
    overfull: Arc<Overfull>,
) -> Result<(tokio::task::JoinHandle<Option<CloseCause>>, SeamRecv), CloseKind>
where
    C: Clock + Clone + Send + 'static,
{
    match (kind, role) {
        (ChannelChoice::Plain, _) => {
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull));
            drop(setup_tx.send(Setup::Plain));
            Ok((writer, SeamRecv::Plain))
        }
        (ChannelChoice::Noise, Role::Responder) => {
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, Arc::clone(&overfull)));
            let mut setup_tx = Some(setup_tx);
            match noise_handshake(
                read,
                engine,
                network_id,
                handshake_within,
                tally,
                &mut setup_tx,
            )
            .await
            {
                Ok(recv) => Ok((writer, recv)),
                Err(kind) => {
                    drop(setup_tx);
                    drop(writer.await);
                    Err(kind)
                }
            }
        }
        (ChannelChoice::Noise, Role::Initiator) => {
            let (write, send, recv) =
                initiator_handshake(read, write, engine, network_id, handshake_within, tally)
                    .await?;
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull));
            if setup_tx
                .send(Setup::Noise {
                    flight: Vec::new(),
                    send,
                })
                .is_err()
            {
                return Err(CloseKind::LocalClose);
            }
            Ok((writer, recv))
        }
    }
}

enum Setup {
    Plain,
    Noise { flight: Vec<u8>, send: SendHalf },
}

async fn write_half(
    mut write: OwnedWriteHalf,
    setup: tokio::sync::oneshot::Receiver<Setup>,
    outbound: ByteQueue,
    overfull: Arc<Overfull>,
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
    let cause = write_capped(&mut write, &outbound, &overfull, |plain| {
        seam.encode(plain)
            .map(Cow::Owned)
            .map_err(|_| CloseKind::RecordRejected)
    })
    .await;
    Some(cause)
}

async fn read_half(
    mut read: OwnedReadHalf,
    mut seam: SeamRecv,
    inbound: mpsc::Sender<Vec<u8>>,
    overfull: Arc<Overfull>,
) -> CloseCause {
    read_capped(&mut read, inbound, &overfull, |chunk| {
        seam.push(chunk).map_err(|_| CloseKind::RecordRejected)
    })
    .await
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
        Ok(Ok(done)) if !fired.load(Ordering::Acquire) => done,
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => return Err(CloseKind::TransportTimeout),
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

fn established_halves<const INITIATOR: bool>(
    established: Established<INITIATOR>,
) -> (SendHalf, shekyl_p2p_transport::RecvHalf) {
    established.split()
}

async fn initiator_handshake<C>(
    read: &mut OwnedReadHalf,
    mut write: OwnedWriteHalf,
    engine: &Handle<C>,
    network_id: &NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
) -> Result<(OwnedWriteHalf, SendHalf, SeamRecv), CloseKind>
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
    tally.queue();
    let tally_job = Arc::clone(tally);
    let network_id = *network_id;
    let fired_job = Arc::clone(&fired);
    let join =
        tokio::task::spawn_blocking(move || initiator_job(network_id, &fired_job, &tally_job));
    let job = await_job(join, &mut wake, &fired).await;
    let (initiator, message1) = match job {
        Ok(Ok(done)) if !fired.load(Ordering::Acquire) => done,
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => {
            ignore(owner.deregister());
            drop(write.shutdown().await);
            return Err(CloseKind::TransportTimeout);
        }
        Ok(Err(SkipOrFail::Failed)) => {
            ignore(owner.deregister());
            drop(write.shutdown().await);
            return Err(CloseKind::TransportHandshakeFailed);
        }
        Err(_) => {
            ignore(owner.deregister());
            tally.dequeue();
            drop(write.shutdown().await);
            return Err(CloseKind::TransportHandshakeFailed);
        }
    };
    let mut flight = Vec::with_capacity(PREFIX_LEN + message1.len());
    flight.extend_from_slice(&prefix_for(&network_id));
    flight.extend_from_slice(&message1);
    if write.write_all(&flight).await.is_err() {
        ignore(owner.deregister());
        return Err(CloseKind::TransportHandshakeFailed);
    }
    let mut prefix = [0u8; PREFIX_LEN];
    if let Err(kind) = read_or_wake(read, &mut prefix, &mut wake, &fired).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(kind);
    }
    if prefix != prefix_for(&network_id) {
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(CloseKind::PrefixMismatch);
    }
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    if let Err(kind) = read_or_wake(read, &mut message2, &mut wake, &fired).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(kind);
    }
    if fired.load(Ordering::Acquire) {
        tally.skip();
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(CloseKind::TransportTimeout);
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
            return Err(CloseKind::TransportTimeout);
        }
        Ok(Err(SkipOrFail::Failed)) | Err(_) => {
            drop(write.shutdown().await);
            return Err(CloseKind::TransportHandshakeFailed);
        }
    };
    Ok((write, send, recv))
}

fn initiator_job(
    network_id: NetworkId,
    fired: &AtomicBool,
    tally: &HandshakeTally,
) -> Result<(Initiator, Vec<u8>), SkipOrFail> {
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    match Initiator::new(&network_id) {
        Ok(done) => {
            tally.dequeue();
            Ok(done)
        }
        Err(_) => {
            tally.dequeue();
            Err(SkipOrFail::Failed)
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
        .map_err(|_| SkipOrFail::Failed);
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
