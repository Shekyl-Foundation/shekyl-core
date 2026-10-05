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
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_capped_stream::{
    accept_error_is_transient, node_gate, read_capped, write_capped, StreamEnds,
};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick};
use shekyl_transport_layer::{
    check_dial, CloseCause, CloseKind, CloseResult, ConnectorId, OpenError, OpenSocket, Sockets,
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
        on_cause(CloseCause::new(CloseKind::DialFailed));
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
            on_cause(CloseCause::new(CloseKind::DialFailed));
            return;
        }
    };
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        settle(reserved, CloseCause::new(CloseKind::DialFailed), &on_cause);
        return;
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(dial_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        settle(reserved, CloseCause::new(CloseKind::DialFailed), &on_cause);
        return;
    }
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let connect = async move {
        let dialed = Instant::now();
        let Ok(mut stream) = TcpStream::connect(proxy).await else {
            return Err(CloseCause::new(CloseKind::DialFailed));
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
                Err(CloseCause::proxy_refused(u16::from(reply)))
            }
            Err(
                SocksError::Io(_)
                | SocksError::Malformed
                | SocksError::AuthRejected { .. }
                | SocksError::AuthFailed { .. },
            ) => {
                drop(stream.shutdown().await);
                Err(CloseCause::new(CloseKind::DialFailed))
            }
        }
    };
    tokio::pin!(connect);
    let stream = tokio::select! {
        biased;
        result = wake.as_mut() => {
            let kind = match result {
                Ok(_) => CloseKind::TransportTimeout,
                Err(_) => CloseKind::DialFailed,
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
        drop(hold);
        return CloseCause::new(CloseKind::LocalClose);
    }

    let overfull_write = Arc::clone(&overfull);
    let gate = node_gate();
    let mut writer = tokio::spawn(async move {
        write_capped(
            &mut write,
            &writer_queue,
            &overfull_write,
            &gate,
            conn,
            |plain| Ok(Cow::Borrowed(plain)),
        )
        .await
    });
    let gate = node_gate();
    let read_fut = read_capped(&mut read, inbound, &overfull, &gate, conn, |chunk| {
        Ok(vec![chunk.to_vec()])
    });
    tokio::pin!(read_fut);
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let mut hold = Some(hold);
    let mut gap_open = true;
    loop {
        tokio::select! {
            biased;
            result = &mut gap_rx, if gap_open => {
                gap_open = false;
                ignore(owner.deregister());
                if result.is_err() {
                    return stop(hold.take(), &mut writer, CloseCause::new(CloseKind::LocalClose)).await;
                }
                tracing::info!(
                    conn,
                    outbound,
                    gap_ns = span_ns(channel_at.elapsed()),
                    "tor session established"
                );
            }
            result = wake.as_mut(), if gap_open => {
                ignore(owner.deregister());
                let kind = match result {
                    Ok(_) => CloseKind::LevinHandshakeTimeout,
                    Err(_) => CloseKind::LocalClose,
                };
                return stop(hold.take(), &mut writer, CloseCause::new(kind)).await;
            }
            read_cause = &mut read_fut => {
                if gap_open {
                    ignore(owner.deregister());
                }
                return stop(hold.take(), &mut writer, read_cause).await;
            }
            write_end = &mut writer => {
                if gap_open {
                    ignore(owner.deregister());
                }
                drop(hold.take());
                return match write_end {
                    Ok(cause) => cause,
                    Err(_) => CloseCause::new(CloseKind::LocalClose),
                };
            }
        }
    }
}

async fn stop(
    hold: Option<shekyl_capped_stream::QueueHold>,
    writer: &mut tokio::task::JoinHandle<CloseCause>,
    cause: CloseCause,
) -> CloseCause {
    drop(hold);
    writer.abort();
    drop(writer.await);
    cause
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}
