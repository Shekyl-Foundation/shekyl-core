// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One Tor stream. Bytes pass through. There is no channel of ours.
//!
//! Outbound, the dial clock is one engine owner covering the SOCKS
//! exchange, circuit build, and rendezvous. Inbound, `accept_tor` is
//! channel established, and the gap timer starts then.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_socks::{connect as socks_connect, Destination, Isolation, SocksError};
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
    let queue = ByteQueue::new(send_queue_bytes);
    let outbound = queue.clone();
    let (in_tx, in_rx) = mpsc::channel(1);
    let overfull = Arc::new(Notify::new());
    let overfull_flag = Arc::new(AtomicBool::new(false));
    let session = Session {
        inbound: in_rx,
        queue,
        overfull: Arc::clone(&overfull),
        overfull_flag: Arc::clone(&overfull_flag),
        established: Some(established_tx),
    };
    if sessions.send(session).is_err() {
        stop.trip(CloseCause::new(CloseKind::LocalClose));
        drop(gap.await);
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
                return finish(&stop_write, &mut write, CloseKind::SendQueueFull).await;
            }
            tokio::select! {
                biased;
                cause = stop_write.wait() => {
                    drop(write.shutdown().await);
                    return cause;
                }
                () = overfull => {
                    return finish(&stop_write, &mut write, CloseKind::SendQueueFull).await;
                }
                next = outbound.pop() => {
                    let Some(bytes) = next else {
                        return finish(&stop_write, &mut write, CloseKind::LocalClose).await;
                    };
                    let n = bytes.len();
                    tokio::select! {
                        biased;
                        cause = stop_write.wait() => {
                            outbound.release(n);
                            drop(write.shutdown().await);
                            return cause;
                        }
                        result = write.write_all(&bytes) => {
                            outbound.release(n);
                            if result.is_err() {
                                return finish(&stop_write, &mut write, CloseKind::IoError).await;
                            }
                        }
                    }
                }
            }
        }
    });
    let read_cause = loop {
        if overfull_flag.load(Ordering::Acquire) {
            stop_read.trip(CloseCause::new(CloseKind::SendQueueFull));
            break CloseCause::new(CloseKind::SendQueueFull);
        }
        let mut buf = [0u8; 8192];
        tokio::select! {
            biased;
            cause = stop_read.wait() => {
                break cause;
            }
            result = read.read(&mut buf) => {
                let n = match result {
                    Ok(0) => {
                        let cause = CloseCause::new(CloseKind::PeerClosed);
                        stop_read.trip(cause);
                        break cause;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        let cause = CloseCause::new(CloseKind::IoError);
                        stop_read.trip(cause);
                        break cause;
                    }
                };
                tokio::select! {
                    biased;
                    cause = stop_read.wait() => {
                        break cause;
                    }
                    result = in_tx.send(buf[..n].to_vec()) => {
                        if result.is_err() {
                            let cause = CloseCause::new(CloseKind::LocalClose);
                            stop_read.trip(cause);
                            break cause;
                        }
                    }
                }
            }
        }
    };
    drop(in_tx);
    let write_cause = writer.await.ok();
    drop(gap.await);
    stop.cause().unwrap_or(write_cause.unwrap_or(read_cause))
}

async fn finish(
    stop: &Stop,
    write: &mut tokio::net::tcp::OwnedWriteHalf,
    kind: CloseKind,
) -> CloseCause {
    let cause = CloseCause::new(kind);
    stop.trip(cause);
    drop(write.shutdown().await);
    cause
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
        stop.trip(CloseCause::new(CloseKind::LocalClose));
        return;
    };
    let now = owner.clock().now();
    let deadline = Tick::new(now.get().saturating_add(gap_within.get()));
    if owner.arm(deadline).is_err() {
        ignore(owner.deregister());
        stop.trip(CloseCause::new(CloseKind::LocalClose));
        return;
    }
    tokio::select! {
        biased;
        _cause = stop.wait() => {
            ignore(owner.deregister());
            return;
        }
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
            stop.trip(CloseCause::new(CloseKind::LevinHandshakeTimeout));
            ignore(owner.deregister());
            return;
        }
    }
    let result = owner.wait_wake_async().await;
    match result {
        Ok(_) | Err(_) => {}
    }
    stop.trip(CloseCause::new(CloseKind::LevinHandshakeTimeout));
    ignore(owner.deregister());
}

fn ignore<E>(result: Result<(), E>) {
    if let Err(_err) = result {}
}

struct Stop {
    notify: Notify,
    cause: Mutex<Option<CloseCause>>,
}

impl Stop {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            cause: Mutex::new(None),
        }
    }

    /// The first cause wins. A later trip does not replace it.
    fn trip(&self, cause: CloseCause) {
        let mut slot = self.cause.lock().expect("stop");
        if slot.is_none() {
            *slot = Some(cause);
            drop(slot);
            self.notify.notify_waiters();
        }
    }

    fn cause(&self) -> Option<CloseCause> {
        *self.cause.lock().expect("stop")
    }

    async fn wait(&self) -> CloseCause {
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            notified.as_mut().enable();
            if let Some(cause) = self.cause() {
                return cause;
            }
            notified.await;
        }
    }
}

/// Outbound bytes. The cap is the only storage limit. A send that does
/// not fit is not stored.
#[derive(Clone)]
pub(crate) struct ByteQueue {
    inner: Arc<Mutex<ByteQueueInner>>,
    data: Arc<tokio::sync::Notify>,
}

struct ByteQueueInner {
    limit: usize,
    used: usize,
    closed: bool,
    items: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) enum PushError {
    Full,
    Closed,
}

impl ByteQueue {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ByteQueueInner {
                limit,
                used: 0,
                closed: false,
                items: VecDeque::new(),
            })),
            data: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(crate) fn try_push(&self, bytes: Vec<u8>) -> Result<(), PushError> {
        let n = bytes.len();
        let mut inner = self.inner.lock().expect("outbound");
        if inner.closed {
            return Err(PushError::Closed);
        }
        if n == 0 {
            return Ok(());
        }
        let Some(next) = inner.used.checked_add(n) else {
            return Err(PushError::Full);
        };
        if next > inner.limit {
            return Err(PushError::Full);
        }
        inner.used = next;
        inner.items.push_back(bytes);
        drop(inner);
        self.data.notify_one();
        Ok(())
    }

    pub(crate) fn release(&self, n: usize) {
        let mut inner = self.inner.lock().expect("outbound");
        inner.used = inner.used.saturating_sub(n);
    }

    pub(crate) fn close(&self) {
        self.inner.lock().expect("outbound").closed = true;
        self.data.notify_waiters();
    }

    pub(crate) async fn pop(&self) -> Option<Vec<u8>> {
        loop {
            let mut notified = std::pin::pin!(self.data.notified());
            notified.as_mut().enable();
            {
                let mut inner = self.inner.lock().expect("outbound");
                if let Some(bytes) = inner.items.pop_front() {
                    return Some(bytes);
                }
                if inner.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}
