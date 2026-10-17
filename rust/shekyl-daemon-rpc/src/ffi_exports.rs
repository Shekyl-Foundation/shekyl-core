// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's start and stop (`DAEMON_CONFIG_CUTOVER.md` §2.3).
//!
//! The Rust `main()` records the RPC section before the C++ remnant is
//! constructed ([`configure`]). The remnant's one start call,
//! [`shekyl_daemon_rpc_start`], carries the core handle and nothing else:
//! it binds every `rpc-admin-listen` endpoint at the admin preset and every
//! `rpc-view-listen` endpoint at the view preset, loopback only, with the
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
use crate::options::{OptionsAbsent, OptionsHandle};
use crate::server::{serve_presets, ServerConfig};

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
    offline: bool,
) -> oneshot::Receiver<Result<(), String>> {
    let (constructed, rx) = oneshot::channel();
    store_offline(offline);
    *slot(&OPTIONS) = Some(Arc::clone(&options));
    *slot(&PENDING) = Some(Pending {
        section,
        options,
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
        constructed,
    }) = slot(&PENDING).take()
    else {
        tracing::error!("daemon-rpc: start called before the section was configured");
        return -1;
    };
    // SAFETY: the caller's contract above.
    match unsafe { start(&section, options, rpc_server_ptr) } {
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
        ..Default::default()
    };
    // Level-triggered: a stop that lands before any acceptor has polled is
    // still observed by `wait_for`. One sender, cloned into every acceptor.
    let (shutdown, shutdown_rx) = watch::channel(false);
    let serve = rt.spawn(async move {
        if let Err(e) = serve_presets(Arc::new(core), config, admin, view, shutdown_rx).await {
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

// ── §4.5 FFI-struct round-trip hooks (DAEMON_SUBMIT_VERDICT.md, F26) ────────
//
// The Rust twins of `shekyl_submit_facts_test_fill` / `_check`
// (daemon_submit_ffi.cpp): per-FIELD writes and reads through *Rust's* view
// of `SubmitFactsFfi`, with the identical seed-derived per-field values, so
// the C++ unit test (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp) can
// drive both directions — C++-writes/Rust-reads and Rust-writes/C++-reads —
// and a field-offset disagreement fails even where a memcpy echo would pass.
// No production callers.

/// splitmix64 over `seed ⊕ field-tweak` — must stay byte-identical to
/// `submit_facts_field_value` in `daemon_submit_ffi.cpp`. Seeds `0` and
/// `u64::MAX` short-circuit to the zeroed/max edge shapes (§4.5).
fn submit_facts_field_value(seed: u64, field: u64) -> u64 {
    if seed == 0 {
        return 0;
    }
    if seed == u64::MAX {
        return u64::MAX;
    }
    let mut z = seed ^ 0x9E37_79B9_7F4A_7C15u64.wrapping_mul(field + 1);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// Deliberate low-byte truncation on every `as u8`: the values must stay
// byte-identical to `submit_facts_test_fill` in daemon_submit_ffi.cpp, whose
// u64-to-u8 field assignments truncate the same way (§4.5 parity hooks).
#[allow(clippy::cast_possible_truncation)]
fn submit_facts_filled(seed: u64) -> crate::ffi::SubmitFactsFfi {
    let mut root = [0u8; 32];
    let root_word = submit_facts_field_value(seed, 5);
    for (i, byte) in root.iter_mut().enumerate() {
        *byte = (root_word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::SubmitFactsFfi {
        in_pool: submit_facts_field_value(seed, 0) as u8,
        in_chain: submit_facts_field_value(seed, 1) as u8,
        ref_block_found: submit_facts_field_value(seed, 2) as u8,
        tree_depth: submit_facts_field_value(seed, 3) as u8,
        in_pool_broadcast: submit_facts_field_value(seed, 10) as u8,
        bond_record_probed: submit_facts_field_value(seed, 12) as u8,
        bond_record_exists: submit_facts_field_value(seed, 13) as u8,
        emission_probed: submit_facts_field_value(seed, 14) as u8,
        emission_claim_conflict: submit_facts_field_value(seed, 15) as u8,
        reserved: [0; 7],
        ref_height: submit_facts_field_value(seed, 4),
        root,
        fee_per_byte: submit_facts_field_value(seed, 6),
        weight_limit: submit_facts_field_value(seed, 8),
        chain_height: submit_facts_field_value(seed, 9),
        in_chain_height: submit_facts_field_value(seed, 11),
        bond_record_bonded_total: submit_facts_field_value(seed, 16),
    }
}

/// Rust-side fill: write seed-derived values into every field through
/// Rust's view of the layout.
///
/// # Safety
///
/// `out` must point to a writable `shekyl_submit_facts_ffi`, or be null
/// (no-op).
#[no_mangle]
pub unsafe extern "C" fn shekyl_submit_facts_rust_fill(
    out: *mut crate::ffi::SubmitFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(submit_facts_filled(seed));
}

/// Rust-side check: read every field through Rust's view and return 0 iff
/// each matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_submit_facts_ffi`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_submit_facts_rust_check(
    facts: *const crate::ffi::SubmitFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == submit_facts_filled(seed) {
        0
    } else {
        -1
    }
}

#[allow(clippy::cast_possible_truncation)]
fn fee_estimate_facts_filled(seed: u64) -> crate::ffi::FeeEstimateFactsFfi {
    crate::ffi::FeeEstimateFactsFfi {
        // Field index 5 below is not a fee-slot index: it seeds a distinct
        // value for the count. Re-indexing it would move every expected
        // value in the harness for no gain.
        fees: std::array::from_fn(|i| submit_facts_field_value(seed, i as u64)),
        fee_count: submit_facts_field_value(seed, 5) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_fee_estimate_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_fee_estimate_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_fee_estimate_facts_rust_fill(
    out: *mut crate::ffi::FeeEstimateFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(fee_estimate_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_fee_estimate_facts`: 0 iff every field
/// matches.
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_fee_estimate_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_fee_estimate_facts_rust_check(
    facts: *const crate::ffi::FeeEstimateFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == fee_estimate_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn net_stats_facts_filled(seed: u64) -> crate::ffi::NetStatsFactsFfi {
    crate::ffi::NetStatsFactsFfi {
        start_time: submit_facts_field_value(seed, 0),
        total_packets_in: submit_facts_field_value(seed, 1),
        total_bytes_in: submit_facts_field_value(seed, 2),
        total_packets_out: submit_facts_field_value(seed, 3),
        total_bytes_out: submit_facts_field_value(seed, 4),
    }
}

/// Rust-side fill of `shekyl_rpc_net_stats_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_net_stats_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_net_stats_facts_rust_fill(
    out: *mut crate::ffi::NetStatsFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(net_stats_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_net_stats_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_net_stats_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_net_stats_facts_rust_check(
    facts: *const crate::ffi::NetStatsFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == net_stats_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Seed-derived per-field values are deliberately truncated into the narrow
// fields — the point is to exercise every byte of the layout (F26).
#[allow(clippy::cast_possible_truncation)]
fn identity_facts_filled(seed: u64) -> crate::ffi::IdentityFactsFfi {
    let mut genesis_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in genesis_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::IdentityFactsFfi {
        nettype: submit_facts_field_value(seed, 0) as u8,
        reserved: [0; 7],
        genesis_hash,
    }
}

/// Rust-side fill of `shekyl_rpc_identity_facts` (layout twin, VC-2).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_identity_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_identity_facts_rust_fill(
    out: *mut crate::ffi::IdentityFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(identity_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_identity_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_identity_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_identity_facts_rust_check(
    facts: *const crate::ffi::IdentityFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == identity_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Seed-derived per-field values are deliberately truncated into the narrow
// fields — the point is to exercise every byte of the layout (F26).
#[allow(clippy::cast_possible_truncation)]
fn chain_tip_facts_filled(seed: u64) -> crate::ffi::ChainTipFactsFfi {
    let mut top_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in top_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::ChainTipFactsFfi {
        chain_height: submit_facts_field_value(seed, 0),
        top_hash,
        target_height: submit_facts_field_value(seed, 2),
        synchronized: submit_facts_field_value(seed, 3) as u8,
        release_build: submit_facts_field_value(seed, 4) as u8,
        reserved: [0; 6],
    }
}

/// Rust-side fill of `shekyl_rpc_chain_tip_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_chain_tip_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_chain_tip_facts_rust_fill(
    out: *mut crate::ffi::ChainTipFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(chain_tip_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_chain_tip_facts`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_chain_tip_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_chain_tip_facts_rust_check(
    facts: *const crate::ffi::ChainTipFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == chain_tip_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn info_chain_facts_filled(seed: u64) -> crate::ffi::InfoChainFactsFfi {
    let mut top_hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 1);
    for (i, byte) in top_hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::InfoChainFactsFfi {
        chain_height: submit_facts_field_value(seed, 0),
        top_hash,
        difficulty_lo: submit_facts_field_value(seed, 2),
        difficulty_hi: submit_facts_field_value(seed, 3),
        cumulative_difficulty_lo: submit_facts_field_value(seed, 4),
        cumulative_difficulty_hi: submit_facts_field_value(seed, 5),
        difficulty_target: submit_facts_field_value(seed, 6),
        total_transactions: submit_facts_field_value(seed, 7),
        block_weight_limit: submit_facts_field_value(seed, 8),
        block_weight_median: submit_facts_field_value(seed, 9),
        adjusted_time: submit_facts_field_value(seed, 10),
        already_generated_coins: submit_facts_field_value(seed, 11),
        total_burned: submit_facts_field_value(seed, 12),
        tx_volume_count_sum: submit_facts_field_value(seed, 13),
        tx_volume_blocks: submit_facts_field_value(seed, 14),
        core_target_height: submit_facts_field_value(seed, 15),
        synchronized: submit_facts_field_value(seed, 16) as u8,
        busy_syncing: submit_facts_field_value(seed, 17) as u8,
        offline: submit_facts_field_value(seed, 18) as u8,
        following_degraded: submit_facts_field_value(seed, 19) as u8,
        protocol_version: submit_facts_field_value(seed, 20) as u8,
        reserved: [0; 3],
    }
}

/// Rust-side fill of `shekyl_rpc_info_chain_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_chain_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_chain_facts_rust_fill(
    out: *mut crate::ffi::InfoChainFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_chain_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_chain_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_chain_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_chain_facts_rust_check(
    facts: *const crate::ffi::InfoChainFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_chain_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn info_status_facts_filled(seed: u64) -> crate::ffi::InfoStatusFactsFfi {
    crate::ffi::InfoStatusFactsFfi {
        start_time: submit_facts_field_value(seed, 0),
        free_space: submit_facts_field_value(seed, 1),
        alt_blocks_count: submit_facts_field_value(seed, 2),
    }
}

/// Rust-side fill of `shekyl_rpc_info_status_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_status_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_status_facts_rust_fill(
    out: *mut crate::ffi::InfoStatusFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_status_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_status_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_status_facts`, or be
/// null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_status_facts_rust_check(
    facts: *const crate::ffi::InfoStatusFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_status_facts_filled(seed) {
        0
    } else {
        -1
    }
}

fn info_peers_facts_filled(seed: u64) -> crate::ffi::InfoPeersFactsFfi {
    crate::ffi::InfoPeersFactsFfi {
        public_incoming_sockets: submit_facts_field_value(seed, 0),
        public_outgoing_sockets: submit_facts_field_value(seed, 1),
        tor_incoming_sockets: submit_facts_field_value(seed, 2),
        tor_outgoing_sockets: submit_facts_field_value(seed, 3),
    }
}

/// Rust-side fill of `shekyl_rpc_info_peers_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_info_peers_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_peers_facts_rust_fill(
    out: *mut crate::ffi::InfoPeersFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(info_peers_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_info_peers_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_info_peers_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_info_peers_facts_rust_check(
    facts: *const crate::ffi::InfoPeersFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == info_peers_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn block_header_facts_filled(seed: u64) -> crate::ffi::BlockHeaderFactsFfi {
    let mut hashes = [[0u8; 32]; 6];
    for (f, hash) in hashes.iter_mut().enumerate() {
        let word = submit_facts_field_value(seed, f as u64);
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = (word >> ((i % 8) * 8)) as u8;
        }
    }
    crate::ffi::BlockHeaderFactsFfi {
        hash: hashes[0],
        prev_hash: hashes[1],
        miner_tx_hash: hashes[2],
        curve_tree_root: hashes[3],
        attestation_root: hashes[4],
        pow_hash: hashes[5],
        height: submit_facts_field_value(seed, 6),
        depth: submit_facts_field_value(seed, 7),
        chain_height: submit_facts_field_value(seed, 8),
        timestamp: submit_facts_field_value(seed, 9),
        difficulty_lo: submit_facts_field_value(seed, 10),
        difficulty_hi: submit_facts_field_value(seed, 11),
        cumulative_difficulty_lo: submit_facts_field_value(seed, 12),
        cumulative_difficulty_hi: submit_facts_field_value(seed, 13),
        reward: submit_facts_field_value(seed, 14),
        block_weight: submit_facts_field_value(seed, 15),
        long_term_weight: submit_facts_field_value(seed, 16),
        num_txes: submit_facts_field_value(seed, 17),
        nonce: submit_facts_field_value(seed, 18) as u32,
        major_version: submit_facts_field_value(seed, 19) as u8,
        minor_version: submit_facts_field_value(seed, 20) as u8,
        orphan_status: submit_facts_field_value(seed, 21) as u8,
        pow_hash_filled: submit_facts_field_value(seed, 22) as u8,
        found: submit_facts_field_value(seed, 23) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_block_header_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_block_header_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_header_facts_rust_fill(
    out: *mut crate::ffi::BlockHeaderFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(block_header_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_block_header_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_block_header_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_header_facts_rust_check(
    facts: *const crate::ffi::BlockHeaderFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == block_header_facts_filled(seed) {
        0
    } else {
        -1
    }
}

// Narrow fields on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn block_hash_facts_filled(seed: u64) -> crate::ffi::BlockHashFactsFfi {
    let mut hash = [0u8; 32];
    let word = submit_facts_field_value(seed, 0);
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = (word >> ((i % 8) * 8)) as u8;
    }
    crate::ffi::BlockHashFactsFfi {
        hash,
        chain_height: submit_facts_field_value(seed, 1),
        found: submit_facts_field_value(seed, 2) as u8,
        reserved: [0; 7],
    }
}

/// Rust-side fill of `shekyl_rpc_block_hash_facts` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_block_hash_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_hash_facts_rust_fill(
    out: *mut crate::ffi::BlockHashFactsFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(block_hash_facts_filled(seed));
}

/// Rust-side check of `shekyl_rpc_block_hash_facts`: 0 iff every field
/// matches the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `facts` must point to a readable `shekyl_rpc_block_hash_facts`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_block_hash_facts_rust_check(
    facts: *const crate::ffi::BlockHashFactsFfi,
    seed: u64,
) -> i32 {
    if facts.is_null() {
        return -1;
    }
    if facts.read() == block_hash_facts_filled(seed) {
        0
    } else {
        -1
    }
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
        let _started = configure(section, Arc::new(OptionsAbsent), true);
        assert_eq!(CoreRpc::p2p_state(), Ok(P2pRead::Offline));
        assert_eq!(CoreRpc::peerlist_sizes(), Ok(P2pRead::Offline));
        store_offline(false);
        assert_eq!(CoreRpc::p2p_state(), Ok(P2pRead::Running(())));
    }
}
