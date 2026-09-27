// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One Tor stream. Bytes pass through. There is no channel of ours.
//!
//! Outbound, the dial clock is one engine owner covering the SOCKS
//! exchange, circuit build, and rendezvous. Inbound, `accept_tor` is
//! channel established, and the gap timer starts then.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, SocksError};
use shekyl_timing_engine::{Clock, Handle, OwnerClass, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, CloseResult, OpenError, Sockets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};

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
    match reserved.close(cause) {
        CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
    }
    on_cause(cause);
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
    let NetworkAddress::Tor { ref host, port } = address else {
        on_cause(CloseCause::new(CloseKind::DialFailed));
        return;
    };
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
        let cause = CloseCause::new(CloseKind::DialFailed);
        match reserved.close(cause) {
            CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
        }
        on_cause(cause);
        return;
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(dial_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        let cause = CloseCause::new(CloseKind::DialFailed);
        match reserved.close(cause) {
            CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
        }
        on_cause(cause);
        return;
    }
    let mut wake = std::pin::pin!(owner.wait_wake_async());
    let host = host.clone();
    let connect = async move {
        let Ok(mut stream) = TcpStream::connect(proxy).await else {
            return Err(CloseCause::new(CloseKind::DialFailed));
        };
        match socks_connect(&mut stream, Destination::Name { host: &host, port }).await {
            Ok(()) => Ok(stream),
            Err(SocksError::Refused { reply }) => {
                drop(stream.shutdown().await);
                Err(CloseCause::proxy_refused(u16::from(reply)))
            }
            Err(SocksError::Io(_) | SocksError::Malformed) => {
                drop(stream.shutdown().await);
                Err(CloseCause::new(CloseKind::DialFailed))
            }
        }
    };
    tokio::pin!(connect);
    let stream = tokio::select! {
        biased;
        result = wake.as_mut() => {
            match result {
                Ok(_) | Err(_) => {}
            }
            ignore(owner.deregister());
            let cause = CloseCause::new(CloseKind::TransportTimeout);
            match reserved.close(cause) {
                CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
            }
            on_cause(cause);
            return;
        }
        result = &mut connect => result,
    };
    ignore(owner.deregister());
    let stream = match stream {
        Ok(stream) => stream,
        Err(cause) => {
            match reserved.close(cause) {
                CloseResult::Recorded(_) | CloseResult::AlreadyClosed => {}
            }
            on_cause(cause);
            return;
        }
    };
    let cause = run(stream, &engine, gap_within, sessions, send_queue_bytes).await;
    match reserved.close(cause) {
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
    let stop = Arc::new(Stop::new());
    let (established_tx, established_rx) = oneshot::channel();
    let gap = tokio::spawn(gap_owner(
        engine.clone(),
        gap_within,
        Arc::clone(&stop),
        established_rx,
    ));
    let queue = SendQueue::new(send_queue_bytes);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Queued>();
    let (in_tx, in_rx) = mpsc::channel(1);
    let overfull = Arc::new(Notify::new());
    let overfull_flag = Arc::new(AtomicBool::new(false));
    let session = Session {
        inbound: in_rx,
        outbound: out_tx,
        queue: queue.clone(),
        overfull: Arc::clone(&overfull),
        overfull_flag: Arc::clone(&overfull_flag),
        established: Some(established_tx),
    };
    if sessions.send(session).is_err() {
        gap.abort();
        return CloseCause::new(CloseKind::LocalClose);
    }
    let stop_read = Arc::clone(&stop);
    let stop_write = Arc::clone(&stop);
    let flag_write = Arc::clone(&overfull_flag);
    let overfull_write = Arc::clone(&overfull);
    let writer = tokio::spawn(async move {
        loop {
            let overfull = overfull_write.notified();
            if flag_write.load(Ordering::Acquire) {
                drop(write.shutdown().await);
                return CloseCause::new(CloseKind::SendQueueFull);
            }
            tokio::select! {
                biased;
                () = stop_write.wait() => {
                    drop(write.shutdown().await);
                    return CloseCause::new(CloseKind::LevinHandshakeTimeout);
                }
                () = overfull => {
                    drop(write.shutdown().await);
                    return CloseCause::new(CloseKind::SendQueueFull);
                }
                next = out_rx.recv() => {
                    let Some(queued) = next else {
                        drop(write.shutdown().await);
                        return CloseCause::new(CloseKind::LocalClose);
                    };
                    if write.write_all(&queued.bytes).await.is_err() {
                        return CloseCause::new(CloseKind::IoError);
                    }
                }
            }
        }
    });
    let read_cause = loop {
        if overfull_flag.load(Ordering::Acquire) {
            break CloseCause::new(CloseKind::SendQueueFull);
        }
        let mut buf = [0u8; 8192];
        tokio::select! {
            biased;
            () = stop_read.wait() => {
                break CloseCause::new(CloseKind::LevinHandshakeTimeout);
            }
            result = read.read(&mut buf) => {
                let n = match result {
                    Ok(0) => break CloseCause::new(CloseKind::PeerClosed),
                    Ok(n) => n,
                    Err(_) => break CloseCause::new(CloseKind::IoError),
                };
                if in_tx.send(buf[..n].to_vec()).await.is_err() {
                    break CloseCause::new(CloseKind::LocalClose);
                }
            }
        }
    };
    drop(in_tx);
    let write_cause = writer.await.ok();
    gap.abort();
    write_cause.unwrap_or(read_cause)
}

async fn gap_owner<C>(
    engine: Handle<C>,
    gap_within: Tick,
    stop: Arc<Stop>,
    established: oneshot::Receiver<()>,
) where
    C: Clock + Clone + Send + Sync + 'static,
{
    let Ok(owner) = engine.register(OwnerClass::Transport) else {
        return;
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(gap_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        return;
    }
    tokio::select! {
        biased;
        result = established => {
            if result.is_ok() {
                ignore(owner.deregister());
                return;
            }
        }
        result = owner.wait_wake_async() => {
            match result {
                Ok(_) | Err(_) => {}
            }
            stop.trip();
            ignore(owner.deregister());
            return;
        }
    }
    let result = owner.wait_wake_async().await;
    match result {
        Ok(_) | Err(_) => {}
    }
    stop.trip();
    ignore(owner.deregister());
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

struct Stop {
    notify: Notify,
    tripped: AtomicBool,
}

impl Stop {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            tripped: AtomicBool::new(false),
        }
    }

    fn trip(&self) {
        self.tripped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.tripped.load(Ordering::Acquire) {
                return;
            }
            notified.await;
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
