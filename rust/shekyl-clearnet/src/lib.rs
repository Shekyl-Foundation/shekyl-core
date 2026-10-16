// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clearnet connector.
//!
//! It is the first caller that keeps a [`shekyl_runtime::Pool`]. The worker
//! count, the blocking cap, the shutdown timeout, and the handshake span are
//! the caller's. This crate does not contain them. The daemon call site
//! labels each one unmeasured until a measurement names it.
//!
//! **The handshake queue is bounded by admission, not by Tokio.**
//! `spawn_blocking` queues without limit once the blocking cap is busy.
//! A handshake is queued only for a connection [`Sockets::accept_clearnet`]
//! has reserved, and that reservation stops at the inbound ceiling. The
//! queue cannot outgrow the connections already admitted. A length on the
//! Tokio queue would refuse a handshake the ceiling had admitted, or admit
//! one the ceiling had refused, so the queue is not given a length that
//! rejects. The same shape as the timing engine's mailbox: admission bounds
//! how many owners exist, and the queue does not apply a second cap.
//!
//! The handshake deadline is one [`OwnerClass::Transport`] owner per
//! connection. It is armed at accept, before the read and before the job
//! is queued, so time spent waiting for a blocking thread counts. The home
//! awaits that owner's wake. When the job is dequeued it checks whether
//! the wake has already been delivered, and skips the handshake if it has.
//! [`HandshakeTally`] counts those skips against the handshakes that were
//! computed. D10's flood test reads that pair.
//!
//! Before the flip, ruling 4's exception is still in force. The option off
//! omits the Noise layer the declaration adds, and the socket bytes are the
//! session bytes, which is what the differential harness compares with
//! epee. The option on follows [`stack_plan`]. Neither arm matches on a
//! network's identity.
//!
//! [`Listener::dial`] checks the addressing cell and then opens an
//! outbound socket. A proxy is SOCKS5 CONNECT (`shekyl-socks`). The
//! initiator handshake uses the same engine owner as the responder.
//! The outbound cap and the socket copy are [`shekyl_capped_stream`].
//! This connector passes the seam as the frame functions.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::NetworkId;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{
    stack_plan, AddedLayer, CloseCause, NetworkColumn, Sockets, StackPlan,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

mod drive;
mod handshake;
mod inode;
mod seam;

#[cfg(unix)]
pub use inode::socket_descriptors;
pub use seam::ChannelChoice;
pub use shekyl_capped_stream::Session;

pub use drive::{
    accept_inbound, accept_one, dial_one, zero_tally, Accept, Admitted, Dial, Inbound,
};
use seam::ChannelChoice as Choice;

/// How many responder handshakes the blocking pool computed, and how many
/// it skipped because the deadline had already fired.
pub struct HandshakeTally {
    pub(crate) computed: AtomicU64,
    pub(crate) skipped: AtomicU64,
    pub(crate) queued: AtomicU64,
}

impl HandshakeTally {
    pub fn computed(&self) -> u64 {
        self.computed.load(Ordering::Acquire)
    }

    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Acquire)
    }

    /// Jobs submitted and not yet finished. Admission is what caps this.
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Acquire)
    }
}

/// Why [`channel_choice`] could not name a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceError {
    /// The encryption cell is not assessed.
    NotUsable,
    /// The plan names a layer this connector does not build.
    LayerNotBuilt,
}

/// The option, until the flip deletes the off arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearnetOption {
    /// Ruling 4. The declaration's Noise layer is not added.
    Off,
    /// Follow the declaration's stack plan.
    On,
}

/// Plaintext or Noise, from the column's plan and the option.
///
/// Off omits whatever layer the plan adds. On builds that layer. The
/// column is an argument. The function does not match on a connector id.
pub fn channel_choice(
    column: NetworkColumn,
    option: ClearnetOption,
) -> Result<ChannelChoice, ChoiceError> {
    let layers = match stack_plan(column) {
        StackPlan::Ready { layers } => layers,
        StackPlan::NotUsable => return Err(ChoiceError::NotUsable),
    };
    // Off is ruling 4's exception. An empty plan is a network that already
    // encrypts. The bytes are the same; the reason is not.
    #[allow(clippy::match_same_arms)]
    match (option, layers) {
        (ClearnetOption::Off, _) => Ok(Choice::Plain),
        (ClearnetOption::On, []) => Ok(Choice::Plain),
        (ClearnetOption::On, [AddedLayer::Noise]) => Ok(Choice::Noise),
        (ClearnetOption::On, _) => Err(ChoiceError::LayerNotBuilt),
    }
}

/// What the caller supplies. None of the spans or the budget live here.
pub struct Config {
    pub listen: SocketAddr,
    pub option: ClearnetOption,
    pub column: NetworkColumn,
    pub network_id: NetworkId,
    pub ceiling: InboundCeiling,
    /// Nanoseconds from accept until the handshake deadline.
    pub handshake_within: Tick,
    /// Passed to [`Pool::shutdown`](shekyl_runtime::Pool::shutdown).
    pub shutdown_timeout: Duration,
    /// Bytes of session plaintext the writer will hold. PWD-T6's
    /// session-established limit plus measurement. Unmeasured until that
    /// derivation is a number. A send that does not fit closes with
    /// [`CloseKind::SendQueueFull`].
    pub send_queue_bytes: usize,
    /// Pause after a transient `accept` error, so the loop does not spin.
    /// Not a protocol deadline.
    pub accept_backoff: Duration,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
}

/// The listener. Drop shuts the pool down with the caller's timeout.
/// Call [`shutdown`](Self::shutdown) from outside a task.
pub struct Listener<C: Clock + Clone> {
    pool: Option<Pool>,
    handle: tokio::runtime::Handle,
    shutdown_timeout: Duration,
    local: SocketAddr,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    pub tally: Arc<HandshakeTally>,
    engine: Handle<C>,
    sockets: Sockets,
    kind: Choice,
    network_id: NetworkId,
    handshake_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    admitted_tx: mpsc::UnboundedSender<Admitted>,
}

impl<C: Clock + Clone> Listener<C> {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("pool still held")
    }

    /// The pool's handle. For `block_on` from outside a task.
    pub fn runtime_handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// [`Pool::shutdown`](shekyl_runtime::Pool::shutdown) with the timeout
    /// from [`Config`]. Not from inside a task.
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
    /// Dial `address`. `proxy` is a SOCKS5 endpoint. `None` connects directly.
    ///
    /// The addressing cell is checked first. A name this connector does not
    /// dial is [`CloseKind::LocalClose`] and opens nothing. A SOCKS refusal
    /// is [`CloseCause::proxy_refused`] with the reply byte.
    pub fn dial(&self, address: NetworkAddress, proxy: Option<SocketAddr>) {
        let dial = drive::Dial {
            address,
            proxy,
            sockets: self.sockets.clone(),
            kind: self.kind,
            network_id: self.network_id,
            dial_within: self.handshake_within,
            proxied_dial_within: self.handshake_within,
            handshake_within: self.handshake_within,
            gap_within: None,
            tally: Arc::clone(&self.tally),
            on_cause: Arc::clone(&self.on_cause),
            send_queue_bytes: self.send_queue_bytes,
            admitted: self.admitted_tx.clone(),
        };
        let engine = self.engine.clone();
        self.handle.spawn(drive::dial_one(dial, engine));
    }
}

impl<C: Clock + Clone> Drop for Listener<C> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

/// Bind on `pool` and accept. `pool` was built with [`shekyl_runtime::runtime`].
///
/// `sockets` is the process-wide admission table. Clones share it. This
/// function does not mint a table: the seam and every connector count the
/// same sockets.
pub fn listen<C>(
    pool: Pool,
    engine: &Handle<C>,
    sockets: Sockets,
    config: &Config,
) -> std::io::Result<Listener<C>>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let kind = channel_choice(config.column, config.option).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "column is not usable")
    })?;
    let handle = pool.handle().clone();
    let listener = pool.block_on(TcpListener::bind(config.listen))?;
    let local = listener.local_addr()?;
    let tally = Arc::new(zero_tally());
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel::<Admitted>();
    pool.spawn(async move {
        while let Some(admitted) = admitted_rx.recv().await {
            // The task holds the other clone and closes it when the socket ends.
            drop(admitted.open);
            drop(admitted.gap);
            if sessions_tx.send(admitted.session).is_err() {
                break;
            }
        }
    });
    let engine_dial = engine.clone();
    let sockets_dial = sockets.clone();
    let admitted_dial = admitted_tx.clone();
    let on_cause = Arc::clone(&config.on_cause);
    let network_id = config.network_id;
    let handshake_within = config.handshake_within;
    let send_queue_bytes = config.send_queue_bytes;
    let shutdown_timeout = config.shutdown_timeout;
    let ceiling = config.ceiling;
    let inbound = Inbound {
        sockets,
        ceiling: move || ceiling,
        kind,
        network_id,
        handshake_within,
        gap_within: None,
        tally: Arc::clone(&tally),
        on_cause: Arc::clone(&config.on_cause),
        send_queue_bytes,
        admitted: admitted_tx,
        backoff: config.accept_backoff,
    };
    let engine = engine.clone();
    pool.spawn(async move {
        accept_inbound(listener, inbound, engine).await;
    });
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout,
        local,
        sessions: sessions_rx,
        tally,
        engine: engine_dial,
        sockets: sockets_dial,
        kind,
        network_id,
        handshake_within,
        send_queue_bytes,
        on_cause,
        admitted_tx: admitted_dial,
    })
}

#[cfg(test)]
mod tests;
