// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One accepted socket. The write half has one task. The handshake
//! deadline is armed at accept, before any read, so time in the
//! blocking queue counts.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_capped_stream::{
    accept_error_is_transient, node_gate, read_capped, write_capped, ByteQueue, Overfull,
    QueueHold, StreamEnds,
};
use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::NetworkId;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, OwnerHandle, Tick};
use shekyl_transport_layer::{
    check_dial, CloseCause, CloseKind, CloseResult, ConnectorId, OpenError, OpenSocket, Sockets,
};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::handshake::{self, Setup};
use crate::seam::{SeamRecv, SeamSend};
use crate::{ChannelChoice, HandshakeTally, Session};

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Responder,
    Initiator,
}

/// One admitted clearnet connection.
///
/// `open` is a clone of the reservation the connection task also holds.
/// The task closes its clone when the socket ends. The recipient may
/// close this one earlier. Dropping it leaves that task to close.
/// `gap` disarms the Levin deadline. `None` means there is no deadline.
pub struct Admitted {
    pub open: OpenSocket,
    pub session: Session,
    pub ip: IpAddr,
    pub port: u16,
    /// Fired when the Levin handshake completes. `None` when this
    /// connection has no gap deadline. Dropping the sender is what ends
    /// the wait; the sender itself lives on the seam row after publish.
    pub gap: Option<oneshot::Sender<()>>,
}

pub struct Dial {
    pub address: NetworkAddress,
    pub proxy: Option<SocketAddr>,
    pub sockets: Sockets,
    pub kind: ChannelChoice,
    pub network_id: NetworkId,
    /// A direct clearnet dial. The three clearnet distributions.
    pub dial_within: Tick,
    /// A dial through `proxy`. The worst measured SOCKS path until that
    /// path has its own distribution. A longer deadline costs only the dialer.
    pub proxied_dial_within: Tick,
    pub handshake_within: Tick,
    /// `Some` arms the Levin gap once the channel is up. `None` publishes
    /// the connection with no gap: the library listener has no handshake
    /// waiting on this socket.
    pub gap_within: Option<Tick>,
    pub tally: Arc<HandshakeTally>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    /// The one place a connected socket is published.
    pub admitted: mpsc::UnboundedSender<Admitted>,
}

pub struct Accept {
    pub stream: TcpStream,
    pub sockets: Sockets,
    pub ceiling: InboundCeiling,
    pub kind: ChannelChoice,
    pub network_id: NetworkId,
    pub handshake_within: Tick,
    /// See [`Dial::gap_within`].
    pub gap_within: Option<Tick>,
    pub tally: Arc<HandshakeTally>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    /// The one place a connected socket is published.
    pub admitted: mpsc::UnboundedSender<Admitted>,
}

/// What an accept loop needs besides the socket it just took.
///
/// `ceiling` is read on every accept, so a later change is visible.
/// `gap_within` of `None` publishes the connection with no Levin deadline.
pub struct Inbound<F> {
    pub sockets: Sockets,
    pub ceiling: F,
    pub kind: ChannelChoice,
    pub network_id: NetworkId,
    pub handshake_within: Tick,
    pub gap_within: Option<Tick>,
    pub tally: Arc<HandshakeTally>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    pub admitted: mpsc::UnboundedSender<Admitted>,
    pub backoff: Duration,
}

pub async fn accept_inbound<C, F>(listener: TcpListener, inbound: Inbound<F>, engine: Handle<C>)
where
    C: Clock + Clone + Send + Sync + 'static,
    F: Fn() -> InboundCeiling + Send,
{
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) if accept_error_is_transient(&error) => {
                (inbound.on_cause)(CloseCause::new(CloseKind::IoError));
                tokio::time::sleep(inbound.backoff).await;
                continue;
            }
            Err(_) => {
                (inbound.on_cause)(CloseCause::new(CloseKind::IoError));
                break;
            }
        };
        let accept = Accept {
            stream,
            sockets: inbound.sockets.clone(),
            ceiling: (inbound.ceiling)(),
            kind: inbound.kind,
            network_id: inbound.network_id,
            handshake_within: inbound.handshake_within,
            gap_within: inbound.gap_within,
            tally: Arc::clone(&inbound.tally),
            on_cause: Arc::clone(&inbound.on_cause),
            send_queue_bytes: inbound.send_queue_bytes,
            admitted: inbound.admitted.clone(),
        };
        tokio::spawn(accept_one(accept, engine.clone()));
    }
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
        gap_within,
        tally,
        on_cause,
        send_queue_bytes,
        admitted,
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
        &reserved,
        &admitted,
        ChannelOpen {
            kind,
            network_id,
            handshake_within,
            gap_within,
            tally,
            send_queue_bytes,
            peer,
            role: Role::Responder,
        },
    )
    .await;
    settle(reserved, cause);
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
        dial_within,
        proxied_dial_within,
        handshake_within,
        gap_within,
        tally,
        on_cause,
        send_queue_bytes,
        admitted,
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
    // The engine refused. That is the host, not the peer, so it does not
    // feed the address forget the way DialFailed does.
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        on_cause(CloseCause::new(CloseKind::LocalClose));
        return;
    };
    let now = owner.clock().now();
    // A proxied dial is the SOCKS exchange plus the proxy's path. The
    // clearnet distributions had no proxy, and a Tor exit is a 3–6 s dial,
    // so the direct clock would time it out. The proxied clock is the
    // worst measured SOCKS path, pending its own distribution.
    let within = if proxy.is_some() {
        proxied_dial_within
    } else {
        dial_within
    };
    let deadline = Tick::new(now.get().saturating_add(within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        on_cause(CloseCause::new(CloseKind::LocalClose));
        return;
    }
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let connect = async {
        let dialed = Instant::now();
        let Ok(mut stream) = TcpStream::connect(target).await else {
            return Err(CloseCause::new(CloseKind::DialFailed));
        };
        if proxy.is_some() {
            match socks_connect(&mut stream, Isolation::Principal, Destination::Ip(dest)).await {
                Ok(()) => {}
                Err(SocksError::Refused { reply }) => {
                    drop(stream.shutdown().await);
                    return Err(CloseCause::proxy_refused(u16::from(reply)));
                }
                Err(
                    SocksError::Io(_)
                    | SocksError::Malformed
                    | SocksError::AuthRejected { .. }
                    | SocksError::AuthFailed { .. },
                ) => {
                    drop(stream.shutdown().await);
                    return Err(CloseCause::new(CloseKind::DialFailed));
                }
            }
        }
        Ok((stream, handshake::span_ns(dialed.elapsed())))
    };
    tokio::pin!(connect);
    let connected = tokio::select! {
        biased;
        result = wake.as_mut() => {
            let kind = match result {
                Ok(_) => CloseKind::TransportTimeout,
                Err(_) => CloseKind::DialFailed,
            };
            Err(CloseCause::new(kind))
        }
        result = &mut connect => result,
    };
    ignore(owner.deregister());
    let (mut stream, connect_ns) = match connected {
        Ok(pair) => pair,
        Err(cause) => {
            on_cause(cause);
            return;
        }
    };
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
    tracing::info!(
        conn = reserved.id().get(),
        connect_ns,
        proxied = proxy.is_some(),
        "clearnet dial connected"
    );
    let cause = serve(
        stream,
        engine,
        &reserved,
        &admitted,
        ChannelOpen {
            kind,
            network_id,
            handshake_within,
            gap_within,
            tally,
            send_queue_bytes,
            peer: dest,
            role: Role::Initiator,
        },
    )
    .await;
    settle(reserved, cause);
    on_cause(cause);
}

fn settle(open: OpenSocket, cause: CloseCause) {
    match open.close(cause) {
        CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
    }
}

fn socket_of(address: &NetworkAddress) -> Option<(IpAddr, u16)> {
    match address {
        NetworkAddress::Ipv4 { ip, port } => Some((IpAddr::V4(*ip), *port)),
        NetworkAddress::Ipv6 { ip, port } => Some((IpAddr::V6(*ip), *port)),
        NetworkAddress::Tor { .. } => None,
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

struct ChannelOpen {
    kind: ChannelChoice,
    network_id: NetworkId,
    handshake_within: Tick,
    gap_within: Option<Tick>,
    tally: Arc<HandshakeTally>,
    send_queue_bytes: usize,
    peer: SocketAddr,
    role: Role,
}

enum GapEnd {
    Established,
    Dropped,
    Timeout,
    Closed,
}

struct GapWatch<C: Clock> {
    owner: OwnerHandle<C>,
    rx: oneshot::Receiver<()>,
}

struct ArmedGap<C: Clock> {
    watch: GapWatch<C>,
    established: oneshot::Sender<()>,
}

fn arm_gap<C>(engine: &Handle<C>, within: Option<Tick>) -> Result<Option<ArmedGap<C>>, CloseCause>
where
    C: Clock + Clone,
{
    let Some(within) = within else {
        return Ok(None);
    };
    let owner = engine
        .register(OwnerClass::Transport)
        .map_err(|_| CloseCause::new(CloseKind::LocalClose))?;
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        return Err(CloseCause::new(CloseKind::LocalClose));
    }
    let (established, rx) = oneshot::channel();
    Ok(Some(ArmedGap {
        watch: GapWatch { owner, rx },
        established,
    }))
}

/// The wake future is pinned once inside this function. Rebuilding it on
/// each poll of the outer select would drop a wake the slot had stored.
async fn watch_gap<C: Clock>(watch: Option<GapWatch<C>>) -> GapEnd {
    let Some(watch) = watch else {
        return std::future::pending().await;
    };
    let mut wake = std::pin::pin!(watch.owner.wait_wake_async());
    let mut rx = watch.rx;
    let end = tokio::select! {
        biased;
        result = &mut rx => match result {
            Ok(()) => GapEnd::Established,
            Err(_) => GapEnd::Dropped,
        },
        result = wake.as_mut() => match result {
            Ok(_) => GapEnd::Timeout,
            Err(_) => GapEnd::Closed,
        },
    };
    ignore(watch.owner.deregister());
    end
}

async fn serve<C>(
    stream: TcpStream,
    engine: Handle<C>,
    open: &OpenSocket,
    admitted: &mpsc::UnboundedSender<Admitted>,
    job: ChannelOpen,
) -> CloseCause
where
    C: Clock + Clone + Send + 'static,
{
    let conn = open.id().get();
    let (mut read, write) = stream.into_split();
    let StreamEnds {
        session,
        writer_queue,
        hold,
        overfull,
        inbound,
    } = StreamEnds::open(job.send_queue_bytes);
    let opened = open_channel(
        &job,
        &mut read,
        write,
        &engine,
        writer_queue,
        Arc::clone(&overfull),
        conn,
    )
    .await;
    let (mut writer, recv) = match opened {
        Ok(opened) => opened,
        Err(kind) => {
            drop(hold);
            return CloseCause::new(kind);
        }
    };
    let (watch, gap_tx) = match arm_gap(&engine, job.gap_within) {
        Ok(Some(armed)) => (Some(armed.watch), Some(armed.established)),
        Ok(None) => (None, None),
        Err(cause) => return end_connection(hold, &mut writer, cause).await,
    };
    let published = Admitted {
        open: open.clone(),
        session,
        ip: job.peer.ip(),
        port: job.peer.port(),
        gap: gap_tx,
    };
    if admitted.send(published).is_err() {
        return end_connection(hold, &mut writer, CloseCause::new(CloseKind::LocalClose)).await;
    }
    let read_fut = read_half(read, recv, inbound, Arc::clone(&overfull), conn);
    tokio::pin!(read_fut);
    let mut gap_open = watch.is_some();
    let gap_fut = watch_gap(watch);
    tokio::pin!(gap_fut);
    loop {
        tokio::select! {
            biased;
            end = gap_fut.as_mut(), if gap_open => {
                gap_open = false;
                match end {
                    GapEnd::Established => {}
                    GapEnd::Dropped | GapEnd::Closed => {
                        return end_connection(hold, &mut writer, CloseCause::new(CloseKind::LocalClose)).await;
                    }
                    GapEnd::Timeout => {
                        return end_connection(
                            hold,
                            &mut writer,
                            CloseCause::new(CloseKind::LevinHandshakeTimeout),
                        )
                        .await;
                    }
                }
            }
            read_cause = &mut read_fut => {
                return end_connection(hold, &mut writer, read_cause).await;
            }
            write_cause = &mut writer => {
                drop(hold);
                return write_cause
                    .ok()
                    .flatten()
                    .unwrap_or(CloseCause::new(CloseKind::LocalClose));
            }
        }
    }
}

async fn end_connection(
    hold: QueueHold,
    writer: &mut tokio::task::JoinHandle<Option<CloseCause>>,
    cause: CloseCause,
) -> CloseCause {
    drop(hold);
    writer.abort();
    drop(writer.await);
    cause
}

async fn open_channel<C>(
    job: &ChannelOpen,
    read: &mut OwnedReadHalf,
    write: OwnedWriteHalf,
    engine: &Handle<C>,
    outbound: ByteQueue,
    overfull: Arc<Overfull>,
    conn: u64,
) -> Result<(tokio::task::JoinHandle<Option<CloseCause>>, SeamRecv), CloseKind>
where
    C: Clock + Clone + Send + 'static,
{
    let started = Instant::now();
    let role_name = match job.role {
        Role::Responder => "responder",
        Role::Initiator => "initiator",
    };
    let kind_name = match job.kind {
        ChannelChoice::Plain => "plain",
        ChannelChoice::Noise => "noise",
    };
    let opened = match (job.kind, job.role) {
        (ChannelChoice::Plain, _) => {
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull, conn));
            drop(setup_tx.send(Setup::Plain));
            Ok((writer, SeamRecv::Plain))
        }
        (ChannelChoice::Noise, Role::Responder) => {
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(
                write,
                setup_rx,
                outbound,
                Arc::clone(&overfull),
                conn,
            ));
            let mut setup_tx = Some(setup_tx);
            match handshake::noise_handshake(
                read,
                engine,
                &job.network_id,
                job.handshake_within,
                &job.tally,
                &mut setup_tx,
                conn,
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
            let (write, send, recv) = handshake::initiator_handshake(
                read,
                write,
                engine,
                &job.network_id,
                job.handshake_within,
                &job.tally,
                conn,
            )
            .await?;
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull, conn));
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
    };
    if opened.is_ok() {
        tracing::info!(
            conn,
            role = role_name,
            kind = kind_name,
            handshake_ns = handshake::span_ns(started.elapsed()),
            "clearnet channel established"
        );
    }
    opened
}

async fn write_half(
    mut write: OwnedWriteHalf,
    setup: tokio::sync::oneshot::Receiver<Setup>,
    outbound: ByteQueue,
    overfull: Arc<Overfull>,
    conn: u64,
) -> Option<CloseCause> {
    let setup = setup.await.ok()?;
    let mut seam = match setup {
        Setup::Plain => SeamSend::Plain,
        Setup::Noise { flight, send } => {
            if !flight.is_empty() {
                let started = Instant::now();
                if !handshake::write_budgeted(&mut write, conn, &flight).await {
                    return Some(CloseCause::new(CloseKind::IoError));
                }
                tracing::info!(
                    conn,
                    write_ns = handshake::span_ns(started.elapsed()),
                    "clearnet responder message2"
                );
            }
            SeamSend::Noise(send)
        }
    };
    let cause = write_capped(
        &mut write,
        &outbound,
        &overfull,
        &node_gate(),
        conn,
        |plain| {
            seam.encode(plain)
                .map(Cow::Owned)
                .map_err(|_| CloseKind::RecordRejected)
        },
    )
    .await;
    Some(cause)
}

async fn read_half(
    mut read: OwnedReadHalf,
    mut seam: SeamRecv,
    inbound: mpsc::Sender<Vec<u8>>,
    overfull: Arc<Overfull>,
    conn: u64,
) -> CloseCause {
    read_capped(&mut read, inbound, &overfull, &node_gate(), conn, |chunk| {
        seam.push(chunk).map_err(|_| CloseKind::RecordRejected)
    })
    .await
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
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
