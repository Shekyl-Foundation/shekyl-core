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
use std::time::{Duration, Instant};

use shekyl_capped_stream::{node_gate, read_capped, write_capped, ByteQueue, Overfull, StreamEnds};
use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::{
    prefix_for, Established, Initiator, NetworkId, Responder, SendHalf, MESSAGE1_LEN, MESSAGE2_LEN,
    PREFIX_LEN,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick, WakeWait};
use shekyl_transport_layer::{
    check_dial, CloseCause, CloseKind, CloseResult, ConnectorId, LinkDirection, MessageClass,
    OpenError, OpenSocket, Sockets,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::seam::{SeamRecv, SeamSend};
use crate::{ChannelChoice, HandshakeTally, Session};

pub(crate) enum Role {
    Responder,
    Initiator,
}

/// A measured span, in nanoseconds, for the D9 distributions. One line
/// per connection at each anchor; nothing here changes what the
/// connection does.
fn span_ns(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// How long a responder's handshake sat in the blocking queue, and how
/// long the pool then spent computing it.
struct PoolSpans {
    queue_ns: u64,
    compute_ns: u64,
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
    /// Fired by `shekyl_zone_session_established`. Dropped before that
    /// closes the connection instead of waiting out the gap.
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
    pub gap_within: Tick,
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
    pub gap_within: Tick,
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
        gap_within,
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
            gap_within,
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
            gap_within,
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
        dial_within,
        proxied_dial_within,
        handshake_within,
        gap_within,
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
        Ok((stream, span_ns(dialed.elapsed())))
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
    let cause = if let Some(tx) = handoff {
        serve(
            stream,
            engine,
            kind,
            network_id,
            handshake_within,
            gap_within,
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
            gap_within,
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

#[allow(clippy::too_many_arguments)]
async fn serve<C>(
    stream: TcpStream,
    engine: Handle<C>,
    kind: ChannelChoice,
    network_id: NetworkId,
    handshake_within: Tick,
    gap_within: Tick,
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
    let conn = reserved.as_ref().map(|open| open.id().get()).unwrap_or(0);
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
        conn,
    )
    .await;
    let (mut writer, recv, message2) = match opened {
        Ok(opened) => opened,
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
    let mut gap_watch = None;
    if let Some(tx) = handoff {
        let Some(open) = reserved.take() else {
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        };
        let Ok(owner) = engine.register(OwnerClass::Transport) else {
            drop(open);
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        };
        let now = owner.clock().now();
        let deadline = Tick::new(now.get().saturating_add(gap_within.get()));
        if owner.arm(deadline).is_err() {
            ignore(owner.deregister());
            drop(open);
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        }
        let (gap_tx, gap_rx) = oneshot::channel();
        let admitted = Admitted {
            open,
            session,
            ip: peer.ip(),
            port: peer.port(),
            gap: Some(gap_tx),
        };
        if tx.send(admitted).is_err() {
            ignore(owner.deregister());
            drop(hold);
            drop(writer.await);
            return CloseCause::new(CloseKind::LocalClose);
        }
        gap_watch = Some((owner, gap_rx));
    } else if sessions.send(session).is_err() {
        drop(hold);
        drop(writer.await);
        return CloseCause::new(CloseKind::LocalClose);
    }
    let read_fut = read_half(read, recv, inbound, Arc::clone(&overfull), conn, message2);
    tokio::pin!(read_fut);
    if let Some((owner, mut gap_rx)) = gap_watch {
        let mut wake = std::pin::pin!(owner.wait_wake_async());
        let mut gap_open = true;
        loop {
            tokio::select! {
                biased;
                result = &mut gap_rx, if gap_open => {
                    gap_open = false;
                    ignore(owner.deregister());
                    if result.is_err() {
                        drop(hold);
                        writer.abort();
                        drop(writer.await);
                        return CloseCause::new(CloseKind::LocalClose);
                    }
                }
                result = wake.as_mut(), if gap_open => {
                    ignore(owner.deregister());
                    drop(hold);
                    writer.abort();
                    drop(writer.await);
                    let kind = match result {
                        Ok(_) => CloseKind::LevinHandshakeTimeout,
                        Err(_) => CloseKind::LocalClose,
                    };
                    return CloseCause::new(kind);
                }
                read_cause = &mut read_fut => {
                    if gap_open {
                        ignore(owner.deregister());
                    }
                    drop(hold);
                    writer.abort();
                    drop(writer.await);
                    return read_cause;
                }
                write_cause = &mut writer => {
                    if gap_open {
                        ignore(owner.deregister());
                    }
                    drop(hold);
                    return write_cause
                        .ok()
                        .flatten()
                        .unwrap_or(CloseCause::new(CloseKind::LocalClose));
                }
            }
        }
    }
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
    conn: u64,
) -> Result<
    (
        tokio::task::JoinHandle<Option<CloseCause>>,
        SeamRecv,
        Option<Arc<Message2Note>>,
    ),
    CloseKind,
>
where
    C: Clock + Clone + Send + 'static,
{
    let started = Instant::now();
    let role_name = match role {
        Role::Responder => "responder",
        Role::Initiator => "initiator",
    };
    let kind_name = match kind {
        ChannelChoice::Plain => "plain",
        ChannelChoice::Noise => "noise",
    };
    let opened = match (kind, role) {
        (ChannelChoice::Plain, _) => {
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull, conn, None));
            drop(setup_tx.send(Setup::Plain));
            Ok((writer, SeamRecv::Plain, None))
        }
        (ChannelChoice::Noise, Role::Responder) => {
            let note = Arc::new(Message2Note::default());
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(
                write,
                setup_rx,
                outbound,
                Arc::clone(&overfull),
                conn,
                Some(Arc::clone(&note)),
            ));
            let mut setup_tx = Some(setup_tx);
            match noise_handshake(
                read,
                engine,
                network_id,
                handshake_within,
                tally,
                &mut setup_tx,
                conn,
            )
            .await
            {
                Ok(recv) => Ok((writer, recv, Some(note))),
                Err(kind) => {
                    drop(setup_tx);
                    drop(writer.await);
                    Err(kind)
                }
            }
        }
        (ChannelChoice::Noise, Role::Initiator) => {
            let (write, send, recv) = initiator_handshake(
                read,
                write,
                engine,
                network_id,
                handshake_within,
                tally,
                conn,
            )
            .await?;
            let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(write_half(write, setup_rx, outbound, overfull, conn, None));
            if setup_tx
                .send(Setup::Noise {
                    flight: Vec::new(),
                    send,
                    handed_off: Instant::now(),
                })
                .is_err()
            {
                return Err(CloseKind::LocalClose);
            }
            Ok((writer, recv, None))
        }
    };
    if opened.is_ok() {
        tracing::info!(
            conn,
            role = role_name,
            kind = kind_name,
            handshake_ns = span_ns(started.elapsed()),
            "clearnet channel established"
        );
    }
    opened
}

enum Setup {
    Plain,
    Noise {
        flight: Vec<u8>,
        send: SendHalf,
        /// When the flight was handed to this task. The wait until the
        /// task runs is the runtime; `write_all` itself is not.
        handed_off: Instant,
    },
}

/// The responder's message-2 write, filled by the writer and read once
/// the peer has answered — by then a lost segment has been retransmitted
/// or it has not. `write_all` cannot tell those apart: it returns when
/// the kernel accepts the segment.
struct Message2Note {
    wait_ns: AtomicU64,
    write_ns: AtomicU64,
    ready: AtomicBool,
}

impl Default for Message2Note {
    fn default() -> Self {
        Self {
            wait_ns: AtomicU64::new(0),
            write_ns: AtomicU64::new(0),
            ready: AtomicBool::new(false),
        }
    }
}

async fn write_half(
    mut write: OwnedWriteHalf,
    setup: tokio::sync::oneshot::Receiver<Setup>,
    outbound: ByteQueue,
    overfull: Arc<Overfull>,
    conn: u64,
    message2: Option<Arc<Message2Note>>,
) -> Option<CloseCause> {
    let setup = setup.await.ok()?;
    let mut seam = match setup {
        Setup::Plain => SeamSend::Plain,
        Setup::Noise {
            flight,
            send,
            handed_off,
        } => {
            if !flight.is_empty() {
                let wait_ns = span_ns(handed_off.elapsed());
                let Some(write_ns) = write_timed(&mut write, conn, &flight).await else {
                    return Some(CloseCause::new(CloseKind::IoError));
                };
                if let Some(note) = &message2 {
                    note.wait_ns.store(wait_ns, Ordering::Release);
                    note.write_ns.store(write_ns, Ordering::Release);
                    note.ready.store(true, Ordering::Release);
                }
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

/// Write `bytes` under the up bucket. The returned time is only
/// `write_all`: the kernel accepting the bytes, not the bucket wait
/// and not a later retransmission.
async fn write_timed(write: &mut OwnedWriteHalf, conn: u64, bytes: &[u8]) -> Option<u64> {
    let gate = node_gate();
    let mut off = 0usize;
    let mut write_ns = 0u64;
    while off < bytes.len() {
        let room = bytes.len() - off;
        let grant = gate
            .acquire(LinkDirection::Up, conn, MessageClass::Session, room as u64)
            .await;
        let grant = usize::try_from(grant).unwrap_or(room).min(room);
        if grant == 0 {
            continue;
        }
        let end = off + grant;
        let started = Instant::now();
        if write.write_all(&bytes[off..end]).await.is_err() {
            gate.refund(LinkDirection::Up, conn, grant as u64, true);
            return None;
        }
        write_ns = write_ns.saturating_add(span_ns(started.elapsed()));
        off = end;
    }
    Some(write_ns)
}

/// Write `bytes` under the up bucket, one grant at a time.
async fn write_budgeted(write: &mut OwnedWriteHalf, conn: u64, bytes: &[u8]) -> bool {
    let gate = node_gate();
    let mut off = 0usize;
    while off < bytes.len() {
        let room = bytes.len() - off;
        let grant = gate
            .acquire(LinkDirection::Up, conn, MessageClass::Session, room as u64)
            .await;
        let grant = usize::try_from(grant).unwrap_or(room).min(room);
        if grant == 0 {
            continue;
        }
        let end = off + grant;
        if write.write_all(&bytes[off..end]).await.is_err() {
            gate.refund(LinkDirection::Up, conn, grant as u64, true);
            return false;
        }
        off = end;
    }
    true
}

async fn read_half(
    mut read: OwnedReadHalf,
    mut seam: SeamRecv,
    inbound: mpsc::Sender<Vec<u8>>,
    overfull: Arc<Overfull>,
    conn: u64,
    message2: Option<Arc<Message2Note>>,
) -> CloseCause {
    // `read_capped` holds `read` for the whole copy, so the probe is a
    // duplicate of the fd. The first decoded chunk is the peer's answer,
    // which cannot arrive before message 2 did: `TCP_INFO` then includes
    // any retransmission of that segment.
    let mut probe = message2.and_then(|note| TcpProbe::from_socket(&read, note));
    read_capped(&mut read, inbound, &overfull, &node_gate(), conn, |chunk| {
        if let Some(probe) = &mut probe {
            probe.log_once(conn);
        }
        seam.push(chunk).map_err(|_| CloseKind::RecordRejected)
    })
    .await
}

/// One read of the responder's message-2 counters, after the peer has
/// answered. The duplicate fd outlives the copy's borrow of the socket.
struct TcpProbe {
    note: Arc<Message2Note>,
    logged: bool,
    #[cfg(target_os = "linux")]
    fd: std::os::fd::OwnedFd,
}

impl TcpProbe {
    fn from_socket(read: &OwnedReadHalf, note: Arc<Message2Note>) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Some(Self {
                note,
                logged: false,
                fd: duplicate_fd(read)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (read, note);
            None
        }
    }

    fn log_once(&mut self, conn: u64) {
        if self.logged || !self.note.ready.load(Ordering::Acquire) {
            return;
        }
        #[cfg(target_os = "linux")]
        let counts = tcp_counts(&self.fd);
        #[cfg(not(target_os = "linux"))]
        let counts: Option<(u32, u32)> = None;
        let Some((total_retrans, retransmits)) = counts else {
            return;
        };
        self.logged = true;
        tracing::info!(
            conn,
            wait_before_write_ns = self.note.wait_ns.load(Ordering::Acquire),
            write_ns = self.note.write_ns.load(Ordering::Acquire),
            total_retrans,
            retransmits,
            "clearnet responder message2"
        );
    }
}

/// `dup` so the copy can borrow the socket while this still names it.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn duplicate_fd(read: &OwnedReadHalf) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let duped = unsafe { libc::dup(read.as_ref().as_raw_fd()) };
    if duped < 0 {
        return None;
    }
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(duped) })
}

/// `tcpi_total_retrans` is the connection's count. `tcpi_retransmits` is
/// how many copies of the current segment are still unacknowledged.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn tcp_counts(fd: &std::os::fd::OwnedFd) -> Option<(u32, u32)> {
    use std::os::fd::AsRawFd;
    let mut info = unsafe { std::mem::zeroed::<libc::tcp_info>() };
    let mut len = u32::try_from(std::mem::size_of::<libc::tcp_info>()).ok()? as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    if rc != 0 {
        return None;
    }
    Some((info.tcpi_total_retrans, u32::from(info.tcpi_retransmits)))
}

async fn noise_handshake<C>(
    read: &mut OwnedReadHalf,
    engine: &Handle<C>,
    network_id: &NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    setup: &mut Option<tokio::sync::oneshot::Sender<Setup>>,
    conn: u64,
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
    if let Err(kind) = read_or_wake(read, &mut prefix, &mut wake, &fired, conn).await {
        note_skip(tally, kind);
        ignore(owner.deregister());
        return Err(kind);
    }
    if prefix != prefix_for(network_id) {
        ignore(owner.deregister());
        return Err(CloseKind::PrefixMismatch);
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
        return Err(CloseKind::TransportTimeout);
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
        Ok(Ok(_) | Err(SkipOrFail::Skipped)) => return Err(CloseKind::TransportTimeout),
        Ok(Err(SkipOrFail::Failed)) | Err(_) => {
            return Err(CloseKind::TransportHandshakeFailed);
        }
    };
    tracing::info!(
        conn,
        queue_ns = spans.queue_ns,
        compute_ns = spans.compute_ns,
        "clearnet responder handshake computed"
    );
    let Some(setup) = setup.take() else {
        return Err(CloseKind::LocalClose);
    };
    let handed_off = Instant::now();
    if setup
        .send(Setup::Noise {
            flight,
            send,
            handed_off,
        })
        .is_err()
    {
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
            .map_err(|_| SkipOrFail::Failed)?;
        let (established, message2) = ready.write_message2().map_err(|_| SkipOrFail::Failed)?;
        Ok((established, message2))
    })();
    tally.dequeue();
    let (established, message2) = result?;
    tally.compute();
    let compute_ns = span_ns(computing.elapsed());
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

async fn initiator_handshake<C>(
    read: &mut OwnedReadHalf,
    mut write: OwnedWriteHalf,
    engine: &Handle<C>,
    network_id: &NetworkId,
    handshake_within: Tick,
    tally: &Arc<HandshakeTally>,
    conn: u64,
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
    let queued = Instant::now();
    let join = tokio::task::spawn_blocking(move || {
        initiator_job(network_id, &fired_job, &tally_job, queued)
    });
    let job = await_job(join, &mut wake, &fired).await;
    let (initiator, message1, spans) = match job {
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
        result = write_budgeted(&mut write, conn, &flight) => result,
    };
    if !wrote {
        ignore(owner.deregister());
        drop(write.shutdown().await);
        return Err(if fired.load(Ordering::Acquire) {
            CloseKind::TransportTimeout
        } else {
            CloseKind::TransportHandshakeFailed
        });
    }
    // The three waits before message 1 is on the wire, separately: the
    // blocking lane (`queue_ns`), the arithmetic (`compute_ns`), and the
    // socket write under the up-link gate (`write_ns`). The responder logs
    // the first two; without the same here a pre-write stall on the
    // initiator has no attribution (floor device, 2026-09-30: 4.3 s
    // between TCP connect and the peer's first read, nothing else logged).
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
        return Err(CloseKind::PrefixMismatch);
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
    queued: Instant,
) -> Result<(Initiator, Vec<u8>, PoolSpans), SkipOrFail> {
    let queue_ns = span_ns(queued.elapsed());
    if fired.load(Ordering::Acquire) {
        tally.skip();
        tally.dequeue();
        return Err(SkipOrFail::Skipped);
    }
    let computing = Instant::now();
    match Initiator::new(&network_id) {
        Ok((initiator, message1)) => {
            tally.dequeue();
            Ok((
                initiator,
                message1,
                PoolSpans {
                    queue_ns,
                    compute_ns: span_ns(computing.elapsed()),
                },
            ))
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
    conn: u64,
) -> Result<(), CloseKind> {
    let gate = node_gate();
    tokio::select! {
        biased;
        result = wake.as_mut() => {
            fired.store(true, Ordering::Release);
            match result {
                Ok(_) | Err(_) => {}
            }
            gate.leave(LinkDirection::Down, conn);
            Err(CloseKind::TransportTimeout)
        }
        result = read_budgeted(read, buf, conn) => {
            result
        }
    }
}

/// Read `buf` under the down bucket. A short socket read is a failure
/// here: the handshake asked for the whole buffer.
async fn read_budgeted(
    read: &mut OwnedReadHalf,
    buf: &mut [u8],
    conn: u64,
) -> Result<(), CloseKind> {
    let gate = node_gate();
    let mut filled = 0usize;
    while filled < buf.len() {
        let room = buf.len() - filled;
        let grant = gate
            .acquire(
                LinkDirection::Down,
                conn,
                MessageClass::Session,
                room as u64,
            )
            .await;
        let grant = usize::try_from(grant).unwrap_or(room).min(room);
        if grant == 0 {
            continue;
        }
        let end = filled + grant.min(buf.len() - filled);
        if read.read_exact(&mut buf[filled..end]).await.is_err() {
            gate.refund(LinkDirection::Down, conn, grant as u64, true);
            return Err(CloseKind::TransportHandshakeFailed);
        }
        let got = end - filled;
        if got < grant {
            gate.refund(LinkDirection::Down, conn, (grant - got) as u64, false);
        }
        filled = end;
    }
    Ok(())
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
