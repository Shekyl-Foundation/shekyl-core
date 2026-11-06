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
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1).
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

/// Structural floor, the same pair the transport runtime is built with.
/// Tokio's unset worker count and its 512 blocking cap are the defaults
/// D5 refuses. These are not a measured budget; the D5 pin replaces them.
fn daemon_rpc_budget() -> RuntimeBudget {
    RuntimeBudget {
        workers: NonZeroUsize::new(2).expect("workers"),
        blocking: NonZeroUsize::new(1).expect("blocking"),
    }
}

/// A running server: its level-triggered stop signal, its runtime and its
/// serve task.
pub struct Running {
    shutdown: watch::Sender<bool>,
    rt: Pool,
    serve: tokio::task::JoinHandle<()>,
}

/// Binds every listener synchronously, then serves them on the node's
/// handles. `armed` is the node's `dev-rpc` switch (`RPC_CHANNEL.md` §6.1).
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
    armed: bool,
) -> Result<Running, String> {
    // The section's one cap; the listeners are loopback only, so the
    // per-address caps the C++ options carried had no population.
    let conn_limits = ConnLimits::checked(u64::from(section.connections_max.get()), 0, 0)?;
    let name = ThreadName::new("daemon-rpc").map_err(|e| format!("thread name refused: {e}"))?;
    let rt = runtime(daemon_rpc_budget(), &name)
        .map_err(|e| format!("the runtime could not start: {e}"))?;
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
    let serve = rt.spawn(async move {
        if let Err(e) = serve_listeners(config, submit_engine, admin, view, shutdown_rx).await {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });
    Ok(Running {
        shutdown,
        rt,
        serve,
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
        } = self;
        // Every acceptor observes this, polled yet or not (`watch` is
        // level-triggered; `notify_waiters` was not and could lose a stop).
        shutdown.send_replace(true);
        drop(rt.block_on(serve));
        drop(rt);
        drop(shutdown);
    }
}
