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

use shekyl_capped_stream::{read_capped, write_capped, StreamEnds};
use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick};
use shekyl_transport_layer::{
    check_dial, CloseCause, CloseKind, CloseResult, ConnectorId, OpenError, OpenSocket, Sockets,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::Session;

pub struct Accept {
    pub stream: TcpStream,
    pub sockets: Sockets,
    pub ceiling: InboundCeiling,
    pub gap_within: Tick,
    pub sessions: mpsc::UnboundedSender<Session>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
}

pub struct Dial {
    pub address: NetworkAddress,
    pub proxy: SocketAddr,
    pub sockets: Sockets,
    pub dial_within: Tick,
    pub gap_within: Tick,
    pub sessions: mpsc::UnboundedSender<Session>,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    pub send_queue_bytes: usize,
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
        sessions,
        on_cause,
        send_queue_bytes,
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
    let cause = run(stream, &engine, gap_within, sessions, send_queue_bytes).await;
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
        sessions,
        on_cause,
        send_queue_bytes,
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
        let Ok(mut stream) = TcpStream::connect(proxy).await else {
            return Err(CloseCause::new(CloseKind::DialFailed));
        };
        match socks_connect(
            &mut stream,
            Isolation::Principal,
            Destination::Name { host: &host, port },
        )
        .await
        {
            Ok(()) => Ok(stream),
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
        Ok(stream) => stream,
        Err(cause) => {
            settle(reserved, cause, &on_cause);
            return;
        }
    };
    let cause = run(stream, &engine, gap_within, sessions, send_queue_bytes).await;
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
    sessions: mpsc::UnboundedSender<Session>,
    send_queue_bytes: usize,
) -> CloseCause
where
    C: Clock + Clone + Send + Sync + 'static,
{
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
    let (established_tx, mut established_rx) = oneshot::channel();
    let session = Session::open(bytes, established_tx);
    if sessions.send(session).is_err() {
        ignore(owner.deregister());
        drop(hold);
        return CloseCause::new(CloseKind::LocalClose);
    }

    let overfull_write = Arc::clone(&overfull);
    let mut writer = tokio::spawn(async move {
        write_capped(&mut write, &writer_queue, &overfull_write, |plain| {
            Ok(Cow::Borrowed(plain))
        })
        .await
    });
    let read_fut = read_capped(&mut read, inbound, &overfull, |chunk| {
        Ok(vec![chunk.to_vec()])
    });
    tokio::pin!(read_fut);
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let mut hold = Some(hold);
    let mut gap_open = true;
    loop {
        tokio::select! {
            biased;
            result = &mut established_rx, if gap_open => {
                gap_open = false;
                ignore(owner.deregister());
                if result.is_err() {
                    return stop(hold.take(), &mut writer, CloseCause::new(CloseKind::LocalClose)).await;
                }
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
