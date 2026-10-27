// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor connector.
//!
//! The Tor stream is the transport contract. There is no Noise layer and
//! no handshake on the blocking pool. The byte cap and the socket copy
//! are [`shekyl_capped_stream`]. Outbound dials an onion through the
//! operator's SOCKS5 proxy ([`shekyl_socks`]). The dial clock is one
//! engine owner covering that exchange, the circuit build, and
//! rendezvous. Inbound is [`Sockets::accept_tor`], then the same copy
//! with the gap as one arm of the wait. Onion-service proof-of-work and
//! `MaxStreams` are the accept bound. This crate does not add another.
//!
//! `--tx-proxy` and `--anonymous-inbound` stay parsed in C++. They arrive
//! here as [`Config`]. A bind failure returns before a listener exists,
//! which is the zone not being inserted. The 60-second Tor liveness poll
//! in `idle_worker` is a timing-table item and is not this connector's.

#![deny(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, Sockets};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

mod drive;
mod publish;
mod replies;

pub use publish::{publish_forward, publish_with_control, InboundPosture, PublishFault};
pub use replies::{proxy_reply_marks, refused, socks_reply_is_our_request};

pub use drive::{accept_inbound, accept_one, dial_one, Accept, Admitted, Dial, Inbound};

/// Caller inputs. The dial span, the gap span, and the send-queue byte
/// cap are unmeasured until a measurement names them.
pub struct Config {
    /// The SOCKS5 proxy outbound dials go through, with the pair it asks
    /// for, if any.
    pub proxy: shekyl_socks::Proxy,
    /// Binds from `--anonymous-inbound`. These are the operator's onions.
    /// They are not a [`ForwardAddr`], so [`publish_forward`] cannot name them.
    pub anonymous_inbound: Vec<OperatorInbound>,
    pub ceiling: InboundCeiling,
    /// Covers the SOCKS exchange, circuit build, and rendezvous.
    pub dial_within: Tick,
    /// Starts when the stream exists. The session layer ends it.
    pub gap_within: Tick,
    pub send_queue_bytes: usize,
    pub accept_backoff: Duration,
    pub shutdown_timeout: Duration,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
}

/// An onion the operator already published. The daemon binds `bind` and
/// does not publish it. There is no conversion to [`ForwardAddr`].
#[derive(Clone, Copy, Debug)]
pub struct OperatorInbound {
    bind: SocketAddr,
}

impl OperatorInbound {
    pub fn new(bind: SocketAddr) -> Self {
        Self { bind }
    }

    pub fn bind(self) -> SocketAddr {
        self.bind
    }
}

/// The loopback port a managed onion forwards to.
///
/// [`listen`] mints this from the forward listener. [`publish_forward`]
/// is the only publisher, and it takes this type. [`OperatorInbound`]
/// does not convert into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardAddr {
    socket: SocketAddr,
}

impl ForwardAddr {
    pub(crate) fn from_bound(socket: SocketAddr) -> std::io::Result<Self> {
        if socket.ip().is_loopback() {
            Ok(Self { socket })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tor forward listener is not loopback",
            ))
        }
    }

    /// The socket `ADD_ONION` targets.
    #[must_use]
    pub fn socket(self) -> SocketAddr {
        self.socket
    }
}

/// One Tor stream's session bytes, plus the gap signal.
///
/// `established` is dropped first. A drop before
/// [`Self::session_established`] ends the connection with
/// [`CloseKind::LocalClose`] instead of waiting out the gap.
pub struct Session {
    established: Option<oneshot::Sender<()>>,
    bytes: shekyl_capped_stream::Session,
}

impl Session {
    pub(crate) fn open(
        bytes: shekyl_capped_stream::Session,
        established: oneshot::Sender<()>,
    ) -> Self {
        Self {
            established: Some(established),
            bytes,
        }
    }

    /// The next bytes off the stream. `None` means the reader stopped.
    /// [`Self::close_cause`] is why.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.bytes.recv().await
    }

    /// The cause the connector stored when it closed this stream.
    ///
    /// [`CloseKind::PeerClosed`] only when the reader saw end-of-file.
    #[must_use]
    pub fn close_cause(&self) -> CloseCause {
        self.bytes.close_cause()
    }

    /// Queue bytes up to the caller's cap. A buffer that does not fit is
    /// not stored, and the connection closes with
    /// [`CloseKind::SendQueueFull`]. The cap is unmeasured until PWD-T6's
    /// session-established limit plus measurement names it.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        self.bytes.try_send(bytes)
    }

    /// The Levin handshake is done. The gap arm is disarmed.
    pub fn session_established(&mut self) {
        if let Some(sender) = self.established.take() {
            match sender.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
    }
}

/// The listener. [`Drop`] shuts the pool down with the caller's timeout.
/// [`shutdown`](Self::shutdown) is the same call, and neither may run
/// inside a task: Tokio panics if a runtime is dropped there. That is
/// [`shekyl_runtime::Pool`]'s rule. Dropping the listener is how a pool
/// that was not shut down explicitly still leaves.
pub struct Listener<C: Clock + Clone> {
    pool: Option<Pool>,
    handle: tokio::runtime::Handle,
    shutdown_timeout: Duration,
    forward: ForwardAddr,
    extra: Vec<SocketAddr>,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    engine: Handle<C>,
    sockets: Sockets,
    proxy: shekyl_socks::Proxy,
    dial_within: Tick,
    gap_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    admitted_tx: mpsc::UnboundedSender<drive::Admitted>,
}

impl<C: Clock + Clone> Listener<C> {
    /// The loopback forward target. Publish takes this value.
    #[must_use]
    pub fn forward_addr(&self) -> ForwardAddr {
        self.forward
    }

    pub fn extra_addrs(&self) -> &[SocketAddr] {
        &self.extra
    }

    pub fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("pool still held")
    }

    pub fn runtime_handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    pub fn shutdown(mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

impl<C> Listener<C>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    /// Dial an onion through the configured proxy.
    pub fn dial(&self, address: NetworkAddress) {
        let dial = Dial {
            address,
            proxy: self.proxy.clone(),
            sockets: self.sockets.clone(),
            dial_within: self.dial_within,
            gap_within: self.gap_within,
            on_cause: Arc::clone(&self.on_cause),
            send_queue_bytes: self.send_queue_bytes,
            admitted: self.admitted_tx.clone(),
        };
        let engine = self.engine.clone();
        self.handle.spawn(dial_one(dial, engine));
    }
}

impl<C: Clock + Clone> Drop for Listener<C> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

/// Bind the loopback forward target and any anonymous-inbound addresses.
///
/// `sockets` is the process-wide admission table. Clones share it, and
/// the ceiling counts every connector on that table. This function keeps
/// a clone and does not mint a table.
///
/// One failed bind drops the listeners that succeeded and returns the
/// error. The caller does not insert the zone. An accepted socket is
/// handed to admission directly. There is no queue of sockets ahead of
/// that check.
pub fn listen<C>(
    pool: Pool,
    engine: &Handle<C>,
    sockets: &Sockets,
    config: &Config,
) -> std::io::Result<Listener<C>>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let handle = pool.handle().clone();
    let (forward_listener, extras) = pool.block_on(bind_all(&config.anonymous_inbound))?;
    let forward = ForwardAddr::from_bound(forward_listener.local_addr()?)?;
    let mut extra_addrs = Vec::with_capacity(extras.len());
    for listener in &extras {
        extra_addrs.push(listener.local_addr()?);
    }
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel::<Admitted>();
    let engine_keep = engine.clone();
    let sockets_keep = sockets.clone();
    let admitted_keep = admitted_tx.clone();
    let on_cause_keep = Arc::clone(&config.on_cause);
    let shutdown_timeout = config.shutdown_timeout;
    let proxy = config.proxy.clone();
    let dial_within = config.dial_within;
    let gap_within = config.gap_within;
    let send_queue_bytes = config.send_queue_bytes;
    let ceiling = config.ceiling;
    let backoff = config.accept_backoff;
    let on_cause = Arc::clone(&config.on_cause);
    handle.spawn(async move {
        while let Some(admitted) = admitted_rx.recv().await {
            drop(admitted.open);
            let session = Session::open(admitted.bytes, admitted.gap);
            if sessions_tx.send(session).is_err() {
                break;
            }
        }
    });
    let mut listeners = extras;
    listeners.push(forward_listener);
    for listener in listeners {
        let inbound = Inbound {
            sockets: sockets.clone(),
            ceiling: move || ceiling,
            gap_within,
            on_cause: Arc::clone(&on_cause),
            send_queue_bytes,
            admitted: admitted_tx.clone(),
            backoff,
        };
        let engine = engine.clone();
        handle.spawn(async move {
            accept_inbound(listener, inbound, engine).await;
        });
    }
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout,
        forward,
        extra: extra_addrs,
        sessions: sessions_rx,
        engine: engine_keep,
        sockets: sockets_keep,
        proxy,
        dial_within,
        gap_within,
        send_queue_bytes,
        on_cause: on_cause_keep,
        admitted_tx: admitted_keep,
    })
}

async fn bind_all(extra: &[OperatorInbound]) -> std::io::Result<(TcpListener, Vec<TcpListener>)> {
    let forward = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let mut bound = Vec::with_capacity(extra.len());
    for addr in extra {
        bound.push(TcpListener::bind(addr.bind()).await?);
    }
    Ok((forward, bound))
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
