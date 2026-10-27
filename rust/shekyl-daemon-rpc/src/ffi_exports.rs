// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's start and stop (`DAEMON_CONFIG_CUTOVER.md` §2.3).
//!
//! The Rust `main()` records the RPC section before the C++ remnant is
//! constructed ([`configure`]). The remnant's one start call,
//! [`shekyl_daemon_rpc_start`], carries the core handle and nothing else:
//! it binds every `rpc-admin-listen` endpoint at the admin listener and every
//! `rpc-view-listen` endpoint at the view listener, loopback only, with the
//! origin list and the one connection cap, and serves them on a runtime held
//! here. It is the last act of §2.2 step 7, so its completion is what
//! `main()` waits for before step 8.
//!
//! The server is stopped by [`stop`] from the Rust stop path (§2.2 step 9,
//! before the remnant's `stop`), or by [`shekyl_daemon_rpc_stop`] from the
//! remnant before it destroys the core on the path where `run` ends first;
//! whichever comes second is a no-op. Either blocks until the in-flight
//! handlers, which hold references into the C++ core, have drained.
//!
//! These exports live in this crate (not `shekyl-ffi`) so that
//! `libshekyl_ffi.a` does not pull in daemon-specific symbols that reference
//! `core_rpc_ffi_*`.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use shekyl_daemon_config::sections::Rpc;
use shekyl_runtime::{runtime, Pool, RuntimeBudget, ThreadName};
use tokio::sync::{oneshot, watch};

use crate::bind::{bind_listener, BoundListener};
use crate::conn_limit::ConnLimits;
use crate::core::CoreRpc;
use crate::handles::Handles;
use crate::options::{OptionsAbsent, OptionsHandle};
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

/// The section the start reads and the sender it completes.
struct Pending {
    section: Rpc,
    options: OptionsHandle,
    handles: Handles,
    /// The node's `dev-rpc` switch (`RPC_CHANNEL.md` §6.1).
    armed: bool,
    constructed: oneshot::Sender<Result<(), String>>,
}

/// A running server: its level-triggered stop signal, its runtime and its
/// serve task.
struct Running {
    shutdown: watch::Sender<bool>,
    rt: Pool,
    serve: tokio::task::JoinHandle<()>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
static RUNNING: Mutex<Option<Running>> = Mutex::new(None);
/// Offline, from the same fact the snapshot carries for C++. The peer
/// methods read it before any dialer call. Default false, so a process
/// that never configured still asks the dialer.
static OFFLINE: AtomicBool = AtomicBool::new(false);
/// The armed-lever switch the last [`configure`] recorded. [`Pending`] is
/// taken at start, so the in-process console cannot read it from there.
/// Default false: a console that runs before configure fails closed.
static ARMED: AtomicBool = AtomicBool::new(false);
/// The options handle the last `configure` recorded, for the in-process
/// console arm, which has the core and not the server's state.
static OPTIONS: Mutex<Option<OptionsHandle>> = Mutex::new(None);

/// The options handle the daemon configured, or the absent handle before
/// any was.
pub(crate) fn options() -> OptionsHandle {
    slot(&OPTIONS)
        .clone()
        .unwrap_or_else(|| Arc::new(OptionsAbsent))
}

fn slot<T>(of: &'static Mutex<Option<T>>) -> MutexGuard<'static, Option<T>> {
    of.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether this daemon is offline. The peer methods answer
/// [`crate::core::P2pRead::Offline`] from this bit and do not call the
/// peer-list exports.
#[must_use]
pub fn offline() -> bool {
    OFFLINE.load(Ordering::Acquire)
}

fn store_offline(offline: bool) {
    OFFLINE.store(offline, Ordering::Release);
}

/// Whether this daemon was started with `dev-rpc`. The in-process console
/// admits an armed lever under this bit. Default false.
#[must_use]
pub(crate) fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

fn store_armed(armed: bool) {
    ARMED.store(armed, Ordering::Release);
}

/// Records the RPC section, whether the daemon is offline, and the options
/// handle (`option_set` and `option_show`'s owner, RT-O26) for the one
/// start call and returns the receiver that call completes: `Ok(())` once
/// every listener is bound and served, `Err` naming the refusal otherwise.
/// The Rust `main()` calls this before the remnant is constructed; a second
/// call before the start replaces the first, whose receiver then never
/// completes. `offline` is the configuration's fact, the same one the
/// snapshot carries for C++.
pub fn configure(
    section: Rpc,
    options: OptionsHandle,
    handles: Handles,
    offline: bool,
    armed: bool,
) -> oneshot::Receiver<Result<(), String>> {
    let (constructed, rx) = oneshot::channel();
    store_offline(offline);
    store_armed(armed);
    *slot(&OPTIONS) = Some(Arc::clone(&options));
    *slot(&PENDING) = Some(Pending {
        section,
        options,
        handles,
        armed,
        constructed,
    });
    rx
}

/// The remnant's one RPC start: serves the configured section on the core.
/// Returns 0, or -1 with the refusal logged and sent to [`configure`]'s
/// receiver, so the operator reads why and the Rust `main()` learns it.
///
/// # Safety
///
/// `rpc_server_ptr` must be a valid pointer to an initialized
/// `core_rpc_server` that stays alive until [`stop`] or
/// [`shekyl_daemon_rpc_stop`] has returned.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_start(rpc_server_ptr: *mut c_void) -> i32 {
    let Some(Pending {
        section,
        options,
        handles,
        armed,
        constructed,
    }) = slot(&PENDING).take()
    else {
        tracing::error!("daemon-rpc: start called before the section was configured");
        return -1;
    };
    // SAFETY: the caller's contract above.
    match unsafe { start(&section, options, handles, armed, rpc_server_ptr) } {
        Ok(running) => {
            *slot(&RUNNING) = Some(running);
            // The receiver is gone only if the entry already gave up.
            let _sent = constructed.send(Ok(()));
            0
        }
        Err(refusal) => {
            tracing::error!("daemon-rpc: {refusal}");
            let _sent = constructed.send(Err(refusal));
            -1
        }
    }
}

/// Binds every listener synchronously, so a refusal or `EADDRINUSE` is the
/// returned error and never a log inside a spawned task, then serves them.
///
/// # Safety
///
/// As [`shekyl_daemon_rpc_start`].
unsafe fn start(
    section: &Rpc,
    options: OptionsHandle,
    handles: Handles,
    armed: bool,
    rpc_server_ptr: *mut c_void,
) -> Result<Running, String> {
    if rpc_server_ptr.is_null() {
        return Err("start called with a null core pointer".to_owned());
    }
    // The section's one cap; the listeners are loopback only, so the
    // per-address caps the C++ options carried have no population.
    let conn_limits = ConnLimits::checked(u64::from(section.connections_max.get()), 0, 0)?;
    // SAFETY: the caller's contract.
    let core = unsafe { CoreRpc::from_raw(rpc_server_ptr) }
        .ok_or_else(|| "core_rpc_server pointer was not a live core".to_owned())?;
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
    let config = ServerConfig {
        cors_origins: section.cors_origins.clone(),
        conn_limits,
        options,
        handles,
        armed,
        ..Default::default()
    };
    // Level-triggered: a stop that lands before any acceptor has polled is
    // still observed by `wait_for`. One sender, cloned into every acceptor.
    let (shutdown, shutdown_rx) = watch::channel(false);
    let serve = rt.spawn(async move {
        if let Err(e) = serve_listeners(Arc::new(core), config, admin, view, shutdown_rx).await {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });
    Ok(Running {
        shutdown,
        rt,
        serve,
    })
}

/// Stops the server if one runs: no new connections, the in-flight handlers
/// drained, the runtime released. Blocks until the drain finishes, because
/// the handlers hold references into the C++ core the caller is about to
/// destroy; `shutdown_background` would free the runtime under a running
/// submit, a use-after-free into the pool mid-commit. A second call, and a
/// call with no server running, are no-ops.
pub fn stop() {
    let Some(Running {
        shutdown,
        rt,
        serve,
    }) = slot(&RUNNING).take()
    else {
        return;
    };
    // Every acceptor observes this, polled yet or not (`watch` is
    // level-triggered; `notify_waiters` was not and could lose a stop).
    shutdown.send_replace(true);
    drop(rt.block_on(serve));
    drop(rt);
    drop(shutdown);
}

/// The remnant's stop: [`stop`], called before it destroys the core on the
/// path where `run` ends before the Rust stop path has run. A no-op when
/// the Rust stop path already ran.
#[no_mangle]
pub extern "C" fn shekyl_daemon_rpc_stop() {
    stop();
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use super::*;
    use crate::core::{CoreRpc, P2pRead};

    /// The offline bit and the section `configure` stores are process-wide.
    /// This puts both back, including when the test panics.
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            store_offline(false);
            slot(&PENDING).take();
            slot(&OPTIONS).take();
        }
    }

    #[test]
    fn an_offline_configure_answers_offline_without_a_dialer() {
        let _reset = Reset;
        // The cap is not read by the peer methods. Any legal section works.
        let section = Rpc {
            admin_listen: Vec::new(),
            view_listen: Vec::new(),
            cors_origins: Vec::new(),
            connections_max: NonZeroU32::MIN,
        };
        let _started = configure(
            section,
            Arc::new(OptionsAbsent),
            Handles::absent(),
            true,
            false,
        );
        assert_eq!(CoreRpc::p2p_state(), Ok(P2pRead::Offline));
        assert_eq!(CoreRpc::peerlist_sizes(), Ok(P2pRead::Offline));
        store_offline(false);
        assert_eq!(CoreRpc::p2p_state(), Ok(P2pRead::Running(())));
    }
}
