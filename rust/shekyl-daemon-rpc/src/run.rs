// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's start and stop (`DAEMON_CONFIG_CUTOVER.md` §2.3).
//!
//! [`start`] binds every `rpc-admin-listen` endpoint at the admin listener
//! and every `rpc-view-listen` endpoint at the view listener, loopback
//! only, with the origin list and the one connection cap, and serves them
//! on a runtime the returned [`Running`] holds. Binding is synchronous, so
//! a refusal or `EADDRINUSE` is the returned error and never a log inside
//! a spawned task. Every route reads the node through the
//! [`Handles`] the composition root supplies; the p2p facts among them
//! are the node's over `shekyl-p2p`'s board
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1). The Tor supervisor is not among
//! them: [`start`] takes its asks beside the handles.
//!
//! [`Running::stop`] stops the server: no new connections, the in-flight
//! handlers drained, the runtime released. It blocks until the drain
//! finishes, because the handlers hold the node's handles, which the
//! caller is about to take down.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_daemon_config::sections::Rpc;
use shekyl_runtime::{runtime, Pool, RuntimeBudget, ThreadName};
use tokio::sync::watch;

use crate::bind::{bind_listener, BoundListener};
use crate::conn_limit::ConnLimits;
use crate::handles::Handles;
use crate::options::OptionsHandle;
use crate::server::{serve_listeners, ServerConfig};
use crate::tor_facts::TorHandle;

/// Structural floor, the same pair the transport runtime is built with.
/// Tokio's unset worker count and its 512 blocking cap are the defaults
/// D5 refuses. These are not a measured budget; the D5 pin replaces them.
fn daemon_rpc_budget() -> RuntimeBudget {
    RuntimeBudget {
        workers: NonZeroUsize::new(2).expect("workers"),
        blocking: NonZeroUsize::new(1).expect("blocking"),
    }
}

/// A running server: its level-triggered stop signal, its runtime, its
/// serve task, and the owner's socket with its watch.
pub struct Running {
    shutdown: watch::Sender<bool>,
    rt: Pool,
    serve: tokio::task::JoinHandle<()>,
    owner: Option<Owner>,
}

/// The server's runtime, and the owner's leg bound on it, before the node
/// opens ([`prepare`]). A pipe registers with the runtime that serves it,
/// so the runtime exists from here.
pub struct Prepared {
    rt: Pool,
    owner: Option<crate::owner::OwnerSocket>,
}

/// Why [`prepare`] refused.
#[derive(Debug)]
pub enum PrepareError {
    /// The runtime could not start, in the operator's words.
    Runtime(String),
    /// The owner's leg refused, as a typed refusal.
    Owner(shekyl_options::Diagnostic),
}

/// Start the server's runtime and bind the owner's leg on it: the start-up
/// dial, the socket or pipe, and the published rendezvous
/// ([`crate::owner::OwnerSocket::bind`]). Called before the node opens, so a
/// second daemon of this account, network and instance refuses with nothing
/// opened (`RPC_CHANNEL.md` §7.1). `owner` is the walk's plan and the
/// network's name; `None` for a service.
///
/// # Errors
///
/// The runtime could not start, or the owner's leg refused.
pub fn prepare(
    owner: Option<(&shekyl_daemon_config::OwnerSocketPlan, &str)>,
) -> Result<Prepared, PrepareError> {
    let name = ThreadName::new("daemon-rpc")
        .map_err(|e| PrepareError::Runtime(format!("thread name refused: {e}")))?;
    let rt = runtime(daemon_rpc_budget(), &name)
        .map_err(|e| PrepareError::Runtime(format!("the runtime could not start: {e}")))?;
    let owner = match owner {
        Some((plan, network)) => {
            let _in_runtime = rt.enter();
            Some(crate::owner::OwnerSocket::bind(plan, network).map_err(PrepareError::Owner)?)
        }
        None => None,
    };
    Ok(Prepared { rt, owner })
}

impl Prepared {
    /// Where the owner's rendezvous is, for the start line; `None` for a
    /// service.
    #[must_use]
    pub fn owner_path(&self) -> Option<&std::path::Path> {
        self.owner.as_ref().map(crate::owner::OwnerSocket::path)
    }
}

/// The owner's leg while it is served: the rendezvous that removes it, and
/// the watch that stops the daemon if it goes first.
struct Owner {
    rendezvous: crate::owner::Rendezvous,
    watch_stop: watch::Sender<bool>,
    watch: tokio::task::JoinHandle<()>,
}

/// What the daemon does when its owner's socket goes: it stops, the one way
/// a stop is asked for (`RPC_CHANNEL.md` §7.1).
pub type OnRendezvousGone = Arc<dyn Fn() + Send + Sync>;

/// Binds every listener synchronously, then serves them on the node's
/// handles, on the runtime [`prepare`] started, with the owner's leg it
/// bound. `tor` is the daemon's Tor supervisor, as `daemon_status` asks it.
/// `armed` is the node's `dev-rpc` switch (`RPC_CHANNEL.md` §6.1). `gone` is
/// what the daemon does if the owner's rendezvous goes.
///
/// # Errors
///
/// The refusal, in the operator's words: a connection cap the section
/// cannot carry, a runtime that could not start, a bind that failed, or a
/// pool not installed for submit.
pub fn start(
    section: &Rpc,
    options: OptionsHandle,
    handles: Handles,
    tor: TorHandle,
    armed: bool,
    prepared: Prepared,
    gone: OnRendezvousGone,
) -> Result<Running, String> {
    let Prepared { rt, owner } = prepared;
    // The section's one cap; the listeners are loopback only, so the
    // per-address caps the C++ options carried had no population.
    let conn_limits = ConnLimits::checked(u64::from(section.connections_max.get()), 0, 0)?;
    let bind = |endpoints: &[SocketAddr]| -> Result<Vec<BoundListener>, String> {
        let mut bound = Vec::with_capacity(endpoints.len());
        for addr in endpoints {
            bound.push(
                rt.block_on(bind_listener(*addr))
                    .map_err(|e| format!("bind failed on {addr}: {e}"))?,
            );
        }
        Ok(bound)
    };
    let admin = bind(&section.admin_listen)?;
    let view = bind(&section.view_listen)?;
    crate::handles::publish_live(&handles);
    let config = ServerConfig {
        cors_origins: section.cors_origins.clone(),
        conn_limits,
        options,
        handles,
        tor,
        armed,
        ..Default::default()
    };
    let Some(shim) = crate::submit::production() else {
        return Err("the node's pool is not installed for submit".to_owned());
    };
    let submit_engine = Arc::new(crate::submit::SubmitEngine::new(
        shim,
        crate::submit::DaemonTxVerifier,
    ));
    // Level-triggered: a stop that lands before any acceptor has polled is
    // still observed by `wait_for`. One sender, cloned into every acceptor.
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (owner, owner_listener) = match owner {
        Some(socket) => {
            let (listener, rendezvous) = socket.into_parts();
            let (watch_stop, watch_rx) = watch::channel(false);
            let watch = rt.spawn(crate::owner::watch(rendezvous.place(), gone, watch_rx));
            (
                Some(Owner {
                    rendezvous,
                    watch_stop,
                    watch,
                }),
                Some(listener),
            )
        }
        None => (None, None),
    };
    let serve = rt.spawn(async move {
        if let Err(e) = serve_listeners(
            config,
            submit_engine,
            admin,
            view,
            owner_listener,
            shutdown_rx,
        )
        .await
        {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });
    Ok(Running {
        shutdown,
        rt,
        serve,
        owner,
    })
}

impl Running {
    /// Stops the server: no new connections, the in-flight handlers
    /// drained, the runtime released. Blocks until the drain finishes;
    /// `shutdown_background` would free the runtime under a running submit.
    pub fn stop(self) {
        let Self {
            shutdown,
            rt,
            serve,
            owner,
        } = self;
        // The owner's socket first: the watch stops, so removing the socket
        // is not read as its going, and then the socket is removed, so no
        // client reaches a daemon that is draining (`RPC_CHANNEL.md` §7.1).
        if let Some(Owner {
            rendezvous,
            watch_stop,
            watch,
        }) = owner
        {
            watch_stop.send_replace(true);
            drop(rt.block_on(watch));
            drop(rendezvous);
        }
        // Every acceptor observes this, polled yet or not (`watch` is
        // level-triggered; `notify_waiters` was not and could lose a stop).
        shutdown.send_replace(true);
        drop(rt.block_on(serve));
        drop(rt);
        drop(shutdown);
    }
}
