// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One Tor stream.
//!
//! The byte copy is [`shekyl_capped_stream`]. The gap is an arm of that
//! wait, not a second task. [`Session::session_established`](crate::Session::session_established)
//! disarms it. Dropping the session completes the same arm with
//! [`CloseKind::LocalClose`], so the admission slot is released without
//! waiting out the gap.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_capped_stream::{
    accept_error_is_transient, node_gate, read_capped, write_capped, InboundEnd, QueueHold,
    StreamEnds,
};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick};
use shekyl_transport_layer::{
    check_dial, socks_reply_is_our_request, CloseCause, CloseKind, CloseResult, ConnectorId,
    OpenError, OpenSocket, Sockets,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// A measured span, in nanoseconds, for the D9 distributions. One line
/// per connection at each anchor; nothing here changes what the
/// connection does.
fn span_ns(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

/// How often a failing Tor SOCKS proxy is named in the log: once a minute
/// at most, never once per dial (Rick, 2026-10-14). A dead proxy fails
/// every dial in turn, and a line per dial would bury the one fact.
const PROXY_WARN_EVERY: Duration = Duration::from_secs(60);

/// When the proxy was last named, and how many failures went unnamed since.
struct ProxyWarn {
    last: Option<Instant>,
    unnamed: u64,
}

impl ProxyWarn {
    const fn new() -> Self {
        Self {
            last: None,
            unnamed: 0,
        }
    }

    /// `Some(unnamed)` when a warning is due at `now`, with the failures
    /// since the last one; `None` while the last is under a minute old.
    fn due(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < PROXY_WARN_EVERY => {
                self.unnamed = self.unnamed.saturating_add(1);
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.unnamed))
            }
        }
    }
}

static PROXY_WARN: std::sync::Mutex<ProxyWarn> = std::sync::Mutex::new(ProxyWarn::new());

/// This node's own Tor SOCKS proxy failed: the TCP connect to it, or an
/// exchange it closed without a reply. Its own close kind, not
/// `LocalClose`: it names the proxy, never the onion.
fn proxy_unavailable(proxy: SocketAddr, why: &'static str) -> CloseCause {
    let due = PROXY_WARN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .due(Instant::now());
    if let Some(unnamed) = due {
        tracing::warn!(
            %proxy,
            why,
            failed_dials_since_last_warning = unnamed,
            "tor's SOCKS proxy is unavailable; dials through it fail until it returns"
        );
    }
    CloseCause::new(CloseKind::ProxyUnavailable)
}

/// A Tor channel. `onion` is the dialed host. Inbound has none: the zone
/// is the address.
///
/// `open` is a clone of the reservation the connection task also holds.
/// `gap` disarms the session deadline. Dropping it ends the wait with
/// [`CloseKind::LocalClose`].
pub struct Admitted {
    pub open: OpenSocket,
    pub bytes: shekyl_capped_stream::Session,
    pub gap: oneshot::Sender<()>,
    pub onion: Option<(String, u16)>,
}

pub struct Accept {
    pub stream: TcpStream,
    pub sockets: Sockets,
    pub ceiling: InboundCeiling,
    pub gap_within: Tick,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    pub admitted: mpsc::UnboundedSender<Admitted>,
}

pub struct Dial {
    pub address: NetworkAddress,
    pub proxy: SocketAddr,
    pub sockets: Sockets,
    pub dial_within: Tick,
    pub gap_within: Tick,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
    pub admitted: mpsc::UnboundedSender<Admitted>,
}

/// What an accept loop needs besides the socket it just took.
///
/// `ceiling` is read on every accept.
pub struct Inbound<F> {
    pub sockets: Sockets,
    pub ceiling: F,
    pub gap_within: Tick,
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
            gap_within: inbound.gap_within,
            on_cause: Arc::clone(&inbound.on_cause),
            send_queue_bytes: inbound.send_queue_bytes,
            admitted: inbound.admitted.clone(),
        };
        tokio::spawn(accept_one(accept, engine.clone()));
    }
}

pub async fn accept_one<C>(accept: Accept, engine: Handle<C>)
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let Accept {
        mut stream,
        sockets,
        ceiling,
        gap_within,
        on_cause,
        send_queue_bytes,
        admitted,
    } = accept;
    let reserved = match sockets.accept_tor(ceiling) {
        Ok(open) => open,
        Err(OpenError::Refused(cause)) => {
            drop(stream.shutdown().await);
            on_cause(cause);
            return;
        }
        Err(OpenError::Exhausted) => {
            drop(stream.shutdown().await);
            on_cause(CloseCause::new(CloseKind::AdmissionRefused));
            return;
        }
    };
    let cause = run(
        stream,
        &engine,
        gap_within,
        send_queue_bytes,
        &reserved,
        &admitted,
        None,
    )
    .await;
    settle(reserved, cause, &on_cause);
}

pub async fn dial_one<C>(dial: Dial, engine: Handle<C>)
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let Dial {
        address,
        proxy,
        sockets,
        dial_within,
        gap_within,
        on_cause,
        send_queue_bytes,
        admitted,
    } = dial;
    let NetworkAddress::Tor { host, port } = &address else {
        on_cause(CloseCause::new(CloseKind::LocalClose));
        return;
    };
    if let Err(cause) = check_dial(ConnectorId::Tor, &address) {
        on_cause(cause);
        return;
    }
    let host = host.clone();
    let onion_host = host.clone();
    let port = *port;
    let reserved = match sockets.open_tor(&address) {
        Ok(open) => open,
        Err(OpenError::Refused(cause)) => {
            on_cause(cause);
            return;
        }
        Err(OpenError::Exhausted) => {
            on_cause(CloseCause::new(CloseKind::LocalClose));
            return;
        }
    };
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        settle(reserved, CloseCause::new(CloseKind::LocalClose), &on_cause);
        return;
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(dial_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        settle(reserved, CloseCause::new(CloseKind::LocalClose), &on_cause);
        return;
    }
    tracing::debug!(
        conn = reserved.id().get(),
        owner = ?owner.id(),
        armed_at = now.get(),
        deadline = deadline.get(),
        "tor dial armed"
    );
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let connect = async move {
        let dialed = Instant::now();
        let Ok(mut stream) = TcpStream::connect(proxy).await else {
            return Err(proxy_unavailable(proxy, "the TCP connect to it failed"));
        };
        let proxy_connect_ns = span_ns(dialed.elapsed());
        match socks_connect(
            &mut stream,
            Isolation::Principal,
            Destination::Name { host: &host, port },
        )
        .await
        {
            Ok(()) => Ok((stream, proxy_connect_ns, span_ns(dialed.elapsed()))),
            Err(SocksError::Refused { reply }) => {
                drop(stream.shutdown().await);
                if socks_reply_is_our_request(u16::from(reply)) {
                    tracing::error!(
                        reply,
                        "tor socks reply is this node's request, not the onion"
                    );
                }
                Err(CloseCause::proxy_refused(u16::from(reply)))
            }
            Err(SocksError::Io(_)) => {
                drop(stream.shutdown().await);
                Err(proxy_unavailable(
                    proxy,
                    "it closed the SOCKS exchange without a reply",
                ))
            }
            Err(
                SocksError::Malformed
                | SocksError::AuthRejected { .. }
                | SocksError::AuthFailed { .. },
            ) => {
                drop(stream.shutdown().await);
                Err(CloseCause::new(CloseKind::LocalClose))
            }
        }
    };
    tokio::pin!(connect);
    let stream = tokio::select! {
        biased;
        result = wake.as_mut() => {
            match &result {
                Ok(wake) => tracing::debug!(
                    conn = reserved.id().get(),
                    owner = ?owner.id(),
                    wake_owner = ?wake.owner,
                    class = ?wake.class,
                    generation = ?wake.generation,
                    wake_deadline = wake.deadline.get(),
                    fired_at = wake.fired_at.get(),
                    armed_deadline = deadline.get(),
                    now = owner.clock().now().get(),
                    "tor dial fired"
                ),
                Err(err) => tracing::debug!(conn = reserved.id().get(), ?err, "tor dial wait ended"),
            }
            let kind = match result {
                Ok(_) => CloseKind::TransportTimeout,
                Err(_) => CloseKind::LocalClose,
            };
            ignore(owner.deregister());
            settle(reserved, CloseCause::new(kind), &on_cause);
            return;
        }
        result = &mut connect => result,
    };
    ignore(owner.deregister());
    let stream = match stream {
        Ok((stream, proxy_connect_ns, dial_ns)) => {
            tracing::info!(
                conn = reserved.id().get(),
                proxy_connect_ns,
                dial_ns,
                "tor dial connected"
            );
            stream
        }
        Err(cause) => {
            settle(reserved, cause, &on_cause);
            return;
        }
    };
    let cause = run(
        stream,
        &engine,
        gap_within,
        send_queue_bytes,
        &reserved,
        &admitted,
        Some((onion_host, port)),
    )
    .await;
    settle(reserved, cause, &on_cause);
}

fn settle(open: OpenSocket, cause: CloseCause, on_cause: &Arc<dyn Fn(CloseCause) + Send + Sync>) {
    match open.close(cause) {
        CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
    }
    on_cause(cause);
}

async fn run<C>(
    stream: TcpStream,
    engine: &Handle<C>,
    gap_within: Tick,
    send_queue_bytes: usize,
    open: &OpenSocket,
    admitted: &mpsc::UnboundedSender<Admitted>,
    onion: Option<(String, u16)>,
) -> CloseCause
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let conn = open.id().get();
    let outbound = onion.is_some();
    let channel_at = Instant::now();
    let (mut read, mut write) = stream.into_split();
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        return CloseCause::new(CloseKind::LocalClose);
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(gap_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        return CloseCause::new(CloseKind::LocalClose);
    }
    tracing::debug!(
        conn,
        outbound,
        owner = ?owner.id(),
        armed_at = now.get(),
        deadline = deadline.get(),
        "tor gap armed"
    );

    let StreamEnds {
        session: bytes,
        writer_queue,
        hold,
        overfull,
        inbound,
    } = StreamEnds::open(send_queue_bytes);
    let (gap_tx, mut gap_rx) = oneshot::channel();
    if admitted
        .send(Admitted {
            open: open.clone(),
            bytes,
            gap: gap_tx,
            onion,
        })
        .is_err()
    {
        ignore(owner.deregister());
        let cause = CloseCause::new(CloseKind::LocalClose);
        inbound.seal(&hold, cause);
        drop(hold);
        return cause;
    }

    let overfull_write = Arc::clone(&overfull);
    let gate = node_gate();
    let mut writer = tokio::spawn(async move {
        let mut stall = shekyl_capped_stream::WriteStall::new(conn);
        // Cold first contact (Rick, 2026-10-13): the dialler's SOCKS success
        // to its first bytes on the wire, the handshake request. The same
        // line on the responder is its first reply.
        let mut first_write = true;
        let cause = write_capped(
            &mut write,
            &writer_queue,
            &overfull_write,
            &gate,
            &mut stall,
            |plain| {
                if first_write {
                    first_write = false;
                    tracing::debug!(
                        conn,
                        outbound,
                        first_write_ns = span_ns(channel_at.elapsed()),
                        "tor first bytes written"
                    );
                }
                Ok(Cow::Borrowed(plain))
            },
        )
        .await;
        tracing::info!(conn, stall = %stall, "write stall");
        cause
    });
    let gate = node_gate();
    let inbound_close = inbound.clone();
    // Cold first contact: the responder's accept to its first bytes read,
    // the dialler's handshake request; on the dialler, the first reply.
    let mut first_read = true;
    // The gap measures the peer's silence (Rick, 2026-10-14): it ends at
    // the peer's first complete Levin frame, read here, not at the strand's
    // verdict, which is this node's own work.
    let mut first_frame = shekyl_levin::FirstFrame::new();
    let frame_in = Arc::new(AtomicBool::new(false));
    let frame_seen = Arc::clone(&frame_in);
    let read_fut = read_capped(&mut read, inbound, &overfull, &gate, conn, |chunk| {
        if first_read {
            first_read = false;
            tracing::debug!(
                conn,
                outbound,
                first_read_ns = span_ns(channel_at.elapsed()),
                "tor first bytes read"
            );
        }
        if !first_frame.complete() && first_frame.feed(chunk) {
            frame_in.store(true, Ordering::Release);
            tracing::debug!(
                conn,
                outbound,
                first_frame_ns = span_ns(channel_at.elapsed()),
                "tor first frame received; the gap ends"
            );
        }
        Ok(vec![chunk.to_vec()])
    });
    tokio::pin!(read_fut);
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let mut hold = Some(hold);
    let mut gap_open = true;
    let mut gap = shekyl_capped_stream::SilenceGap::new();
    let mut verdict_open = true;
    loop {
        // Buffered input first: a frame that arrived before the deadline is
        // read even when this task resumes after it, and only then is the
        // gap's wake looked at (`SilenceGap`).
        tokio::select! {
            biased;
            read_cause = &mut read_fut => {
                if gap_open {
                    ignore(owner.deregister());
                }
                return stop(
                    &inbound_close,
                    hold.take(),
                    WriteJoin::Pending(&mut writer),
                    read_cause,
                )
                .await;
            }
            result = &mut gap_rx, if verdict_open => {
                verdict_open = false;
                if result.is_err() {
                    if gap_open {
                        ignore(owner.deregister());
                    }
                    return stop(
                        &inbound_close,
                        hold.take(),
                        WriteJoin::Pending(&mut writer),
                        CloseCause::new(CloseKind::LocalClose),
                    )
                    .await;
                }
                tracing::info!(
                    conn,
                    outbound,
                    gap_ns = span_ns(channel_at.elapsed()),
                    "tor session established"
                );
            }
            result = std::future::poll_fn(|cx| gap.poll(&frame_seen, wake.as_mut(), cx)), if gap_open => {
                gap_open = false;
                ignore(owner.deregister());
                let Some(result) = result else {
                    continue;
                };
                // Cold first contact (2026-10-14): on one responder the gap
                // fired 1.8 s early, in the same half-millisecond as the
                // dialer loops' wakes. The delivered wake, against what was
                // armed, says whose it was.
                match &result {
                    Ok(wake) => tracing::debug!(
                        conn,
                        outbound,
                        owner = ?owner.id(),
                        wake_owner = ?wake.owner,
                        class = ?wake.class,
                        generation = ?wake.generation,
                        wake_deadline = wake.deadline.get(),
                        fired_at = wake.fired_at.get(),
                        armed_deadline = deadline.get(),
                        now = owner.clock().now().get(),
                        "tor gap fired"
                    ),
                    Err(err) => tracing::debug!(conn, outbound, ?err, "tor gap wait ended"),
                }
                let kind = match result {
                    Ok(_) => CloseKind::LevinHandshakeTimeout,
                    Err(_) => CloseKind::LocalClose,
                };
                let cause = CloseCause::new(kind);
                return stop(
                    &inbound_close,
                    hold.take(),
                    WriteJoin::Pending(&mut writer),
                    cause,
                )
                .await;
            }
            write_end = &mut writer => {
                if gap_open {
                    ignore(owner.deregister());
                }
                let cause = match write_end {
                    Ok(cause) => cause,
                    Err(_) => CloseCause::new(CloseKind::LocalClose),
                };
                return stop(&inbound_close, hold.take(), WriteJoin::Finished, cause).await;
            }
        }
    }
}

/// Whether `select` has already polled the writer to completion.
///
/// A completed [`tokio::task::JoinHandle`] panics if it is polled again.
/// [`WriteJoin::Finished`] is that arm. The others still hold a running task.
enum WriteJoin<'a> {
    Pending(&'a mut tokio::task::JoinHandle<CloseCause>),
    Finished,
}

/// Seal the session. Abort the writer only when this select has not joined it.
///
/// `hold` is absent only when a previous arm already took it. The inbound
/// cause is recorded either way.
async fn stop(
    inbound: &InboundEnd,
    hold: Option<QueueHold>,
    writer: WriteJoin<'_>,
    cause: CloseCause,
) -> CloseCause {
    if let Some(hold) = hold.as_ref() {
        inbound.seal(hold, cause);
    } else {
        inbound.close(cause);
    }
    drop(hold);
    if let WriteJoin::Pending(writer) = writer {
        writer.abort();
        drop(writer.await);
    }
    cause
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

#[cfg(test)]
mod tests {
    use super::{ProxyWarn, PROXY_WARN_EVERY};

    /// The proxy is named on its first failure, then not again for a
    /// minute however many dials fail, and the next warning counts them.
    #[test]
    fn a_failing_proxy_is_named_once_a_minute_with_the_dials_in_between() {
        let start = std::time::Instant::now();
        let mut warn = ProxyWarn::new();
        assert_eq!(warn.due(start), Some(0));
        for i in 1..=50u32 {
            let at = start + PROXY_WARN_EVERY * i / 51;
            assert_eq!(warn.due(at), None, "dial {i} within the minute");
        }
        assert_eq!(warn.due(start + PROXY_WARN_EVERY), Some(50));
        assert_eq!(warn.due(start + PROXY_WARN_EVERY * 3 / 2), None);
    }

    use super::*;

    #[tokio::test]
    async fn a_joined_writer_is_not_polled_again() {
        let ends = StreamEnds::open(8);
        let mut writer = tokio::spawn(async { CloseCause::new(CloseKind::IoError) });
        let joined = (&mut writer).await.expect("writer joined");
        let cause = stop(&ends.inbound, Some(ends.hold), WriteJoin::Finished, joined).await;
        assert_eq!(cause.kind(), CloseKind::IoError);
    }
}
