// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C FFI entry points for starting/stopping the Axum daemon RPC server.
//!
//! These are `#[no_mangle] extern "C"` functions called from `daemon.cpp`
//! via the declarations in `shekyl_ffi.h`. They live in this crate (not
//! `shekyl-ffi`) so that `libshekyl_ffi.a` does not pull in daemon-specific
//! symbols that reference `core_rpc_ffi_*`.

use std::os::raw::c_char;

/// Opaque handle returned to C++ for a running daemon RPC server.
#[repr(C)]
pub struct ShekylDaemonRpcHandle {
    shutdown: *const tokio::sync::Notify,
    rt: *const tokio::runtime::Runtime,
    /// The serve task's join handle. `shekyl_daemon_rpc_stop` blocks on it so
    /// the graceful-shutdown drain of in-flight handlers (which hold live
    /// references into the C++ core) completes before the runtime — and, on
    /// return to C++, the core — is torn down.
    serve: *mut tokio::task::JoinHandle<()>,
}

/// Start the Axum daemon RPC server on a dedicated Tokio runtime.
///
/// Returns an opaque handle, or null on failure. Caller must eventually call
/// `shekyl_daemon_rpc_stop` to shut down.
///
/// The TCP bind is performed synchronously before the handle is returned, so a
/// bind failure (e.g. EADDRINUSE) yields a null return the caller can treat as
/// fatal — the failure is never swallowed inside an async serve task. Multiple
/// independent instances may run concurrently (e.g. a main and a restricted
/// port); each returned handle owns its own runtime and must be stopped
/// individually.
///
/// # Safety
///
/// - `rpc_server_ptr` must be a valid pointer to an initialized `core_rpc_server`,
///   or null (returns null immediately).
/// - `bind_host` and `bind_port` must be valid null-terminated C strings, or
///   null (returns null): the operator's `--rpc-bind-ip` / `--rpc-bind-port`
///   values as given.
/// - `bind_host_v6` is the operator's `--rpc-bind-ipv6-address` (or the
///   restricted twin) when `--rpc-use-ipv6` is set, or null. Rust parses it
///   with the same port, classifies it, and binds a second socket on this
///   handle when it is a different address; C++ does not start a second
///   server.
///   Rust parses both (`bind::parse_bind` / `bind::listen_addrs`) and
///   decides the listen posture (`bind::bind_listener`); C++ composes
///   nothing.
/// - `cors_origins` may be null (default-deny) or a null-terminated
///   comma-separated allow-list string.
/// - `max_connections`, `max_connections_per_public_ip`, and
///   `max_connections_per_private_ip` are the concurrent-connection caps
///   (0 = unlimited) as given; `ConnLimits::checked` validates them here.
///
/// Parse, cap, and bind refusals are logged with their reason before the
/// null handle is returned, so the operator reads why, not "failed to start".
/// - The pointed-to `core_rpc_server` must remain alive for the lifetime of the
///   returned handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_start(
    rpc_server_ptr: *mut std::ffi::c_void,
    bind_host: *const c_char,
    bind_port: *const c_char,
    bind_host_v6: *const c_char,
    restricted: bool,
    cors_origins: *const c_char,
    max_connections: u64,
    max_connections_per_public_ip: u64,
    max_connections_per_private_ip: u64,
) -> *mut ShekylDaemonRpcHandle {
    if rpc_server_ptr.is_null() || bind_host.is_null() || bind_port.is_null() {
        return std::ptr::null_mut();
    }

    let (Ok(host), Ok(port)) = (
        std::ffi::CStr::from_ptr(bind_host).to_str(),
        std::ffi::CStr::from_ptr(bind_port).to_str(),
    ) else {
        tracing::error!("daemon-rpc: --rpc-bind-ip / --rpc-bind-port are not valid UTF-8");
        return std::ptr::null_mut();
    };
    let host_v6 = if bind_host_v6.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(bind_host_v6).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                tracing::error!("daemon-rpc: --rpc-bind-ipv6-address is not valid UTF-8");
                return std::ptr::null_mut();
            }
        }
    };
    let addrs = match crate::bind::listen_addrs(host, port, host_v6) {
        Ok(addrs) => addrs,
        Err(e) => {
            tracing::error!("daemon-rpc: {e}");
            return std::ptr::null_mut();
        }
    };
    let conn_limits = match crate::conn_limit::ConnLimits::checked(
        max_connections,
        max_connections_per_public_ip,
        max_connections_per_private_ip,
    ) {
        Ok(limits) => limits,
        Err(e) => {
            tracing::error!("daemon-rpc: {e}");
            return std::ptr::null_mut();
        }
    };

    let cors = if cors_origins.is_null() {
        Vec::new()
    } else {
        match std::ffi::CStr::from_ptr(cors_origins).to_str() {
            Ok("") => Vec::new(),
            Ok(s) => {
                let parsed: Vec<String> = s
                    .split(',')
                    .map(str::trim)
                    .filter(|o| !o.is_empty())
                    .map(str::to_owned)
                    .collect();
                if parsed.is_empty() {
                    // A non-empty value that trims to nothing (e.g. " , " or a
                    // stray trailing comma) is almost certainly a misconfig, and
                    // would otherwise be silently indistinguishable from unset
                    // (CORS default-deny). Surface it instead of failing quietly.
                    tracing::warn!(
                        raw = %s,
                        "--rpc-access-control-origins contained no usable origins after \
                         trimming; CORS is default-deny (all cross-origin requests rejected)"
                    );
                }
                parsed
            }
            Err(_) => {
                tracing::error!("daemon-rpc: --rpc-access-control-origins is not valid UTF-8");
                return std::ptr::null_mut();
            }
        }
    };

    let core = match crate::core::CoreRpc::from_raw(rpc_server_ptr) {
        Some(c) => std::sync::Arc::new(c),
        None => {
            tracing::error!("daemon-rpc: core_rpc_server pointer was not a live core");
            return std::ptr::null_mut();
        }
    };

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("daemon-rpc")
        .build()
    else {
        tracing::error!("daemon-rpc: failed to build the tokio runtime");
        return std::ptr::null_mut();
    };

    // Bind every family synchronously so a refusal or EADDRINUSE is a null
    // handle, not a log inside a spawned task. A later family failing drops
    // the sockets already bound on this return.
    let mut bound = Vec::with_capacity(addrs.len());
    for addr in addrs {
        match rt.block_on(crate::bind::bind_listener(addr)) {
            Ok(listener) => bound.push((addr, listener)),
            Err(e) => {
                tracing::error!("daemon-rpc bind failed on {addr}: {e}");
                return std::ptr::null_mut();
            }
        }
    }

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_for_server = shutdown.clone();

    let serve = rt.spawn(async move {
        let mut bound = bound.into_iter();
        let (addr, listener) = bound
            .next()
            .expect("listen_addrs yields at least the primary");
        let config = crate::server::ServerConfig {
            bind_addr: addr,
            restricted,
            cors_origins: cors.clone(),
            conn_limits,
            ..Default::default()
        };
        let extra = bound.next().map(|(addr, listener)| {
            (
                crate::server::ServerConfig {
                    bind_addr: addr,
                    restricted,
                    cors_origins: cors.clone(),
                    conn_limits,
                    ..Default::default()
                },
                listener,
            )
        });
        let log_err = |e| tracing::error!("daemon-rpc server error: {e}");
        match extra {
            None => {
                if let Err(e) =
                    crate::server::serve_with_listener(core, config, listener, shutdown_for_server)
                        .await
                {
                    log_err(e);
                }
            }
            Some((config_v6, listener_v6)) => {
                let (a, b) = tokio::join!(
                    crate::server::serve_with_listener(
                        core.clone(),
                        config,
                        listener,
                        shutdown_for_server.clone(),
                    ),
                    crate::server::serve_with_listener(
                        core,
                        config_v6,
                        listener_v6,
                        shutdown_for_server,
                    ),
                );
                if let Err(e) = a {
                    log_err(e);
                }
                if let Err(e) = b {
                    log_err(e);
                }
            }
        }
    });

    let handle = Box::new(ShekylDaemonRpcHandle {
        shutdown: std::sync::Arc::into_raw(shutdown),
        rt: Box::into_raw(Box::new(rt)).cast_const(),
        serve: Box::into_raw(Box::new(serve)),
    });

    Box::into_raw(handle)
}

/// Stop the Axum daemon RPC server and release all resources.
///
/// # Safety
///
/// - `handle` must be a pointer returned by `shekyl_daemon_rpc_start`, or null
///   (no-op). Each handle must be stopped exactly once.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_stop(handle: *mut ShekylDaemonRpcHandle) {
    if handle.is_null() {
        return;
    }
    let handle = Box::from_raw(handle);

    // Signal graceful shutdown: axum stops accepting and lets in-flight
    // handlers run to completion — including a submit mid-Phase-C on the
    // blocking pool, whose closure holds live references into the C++ core.
    if !handle.shutdown.is_null() {
        let notify = std::sync::Arc::from_raw(handle.shutdown);
        // One waiter today, two when --rpc-use-ipv6 bound a second family
        // on this handle. `notify_one` would leave the other serving.
        notify.notify_waiters();
    }

    if !handle.rt.is_null() {
        let rt = Box::from_raw(handle.rt.cast_mut());
        // Block until the serve task's graceful drain finishes BEFORE the
        // runtime is dropped and control returns to C++ (which then destroys
        // the core_rpc_server / core the in-flight handlers reference).
        // `shutdown_background()` returned immediately and could free the
        // runtime out from under a running blocking submit — a use-after-free
        // into the C++ pool/blockchain, potentially mid-commit.
        if !handle.serve.is_null() {
            let serve = *Box::from_raw(handle.serve);
            drop(rt.block_on(serve));
        }
        drop(rt);
    } else if !handle.serve.is_null() {
        // No runtime to drive the join (should not happen): reclaim the box
        // so it is not leaked. The task cannot be awaited without a runtime.
        drop(Box::from_raw(handle.serve));
    }
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
        fee_quantization_mask: submit_facts_field_value(seed, 7),
        weight_limit: submit_facts_field_value(seed, 8),
        chain_height: submit_facts_field_value(seed, 9),
        in_chain_height: submit_facts_field_value(seed, 11),
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

// Narrow field on purpose (see chain_tip_facts_filled).
#[allow(clippy::cast_possible_truncation)]
fn hardfork_entry_filled(seed: u64) -> crate::ffi::HardforkEntryFfi {
    crate::ffi::HardforkEntryFfi {
        version: submit_facts_field_value(seed, 0) as u8,
        reserved: [0; 7],
        height: submit_facts_field_value(seed, 1),
    }
}

/// Rust-side fill of `shekyl_rpc_hardfork_entry` (layout twin, RK-D3).
///
/// # Safety
///
/// `out` must point to a writable `shekyl_rpc_hardfork_entry`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_hardfork_entry_rust_fill(
    out: *mut crate::ffi::HardforkEntryFfi,
    seed: u64,
) {
    if out.is_null() {
        return;
    }
    out.write(hardfork_entry_filled(seed));
}

/// Rust-side check of `shekyl_rpc_hardfork_entry`: 0 iff every field matches
/// the seed derivation (-1 otherwise, including null input).
///
/// # Safety
///
/// `entry` must point to a readable `shekyl_rpc_hardfork_entry`, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_rpc_hardfork_entry_rust_check(
    entry: *const crate::ffi::HardforkEntryFfi,
    seed: u64,
) -> i32 {
    if entry.is_null() {
        return -1;
    }
    if entry.read() == hardfork_entry_filled(seed) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation itself, pinned by vectors so a Rust-side edit cannot
    /// silently diverge from the C++ constant chain (the cross-language
    /// round-trip in tests/unit_tests/daemon_submit_ffi_roundtrip.cpp is
    /// the authoritative gate; this catches drift at `cargo test` speed).
    #[test]
    fn field_value_edges_and_tweak_separation() {
        assert_eq!(submit_facts_field_value(0, 7), 0);
        assert_eq!(submit_facts_field_value(u64::MAX, 3), u64::MAX);
        // Distinct fields derive distinct values for a nontrivial seed —
        // the property that makes same-width offset swaps detectable.
        let seed = 0xDEAD_BEEF_CAFE_F00D;
        let values: Vec<u64> = (0..12).map(|f| submit_facts_field_value(seed, f)).collect();
        let mut deduped = values.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), values.len());
    }

    #[test]
    fn rust_fill_check_round_trips() {
        for seed in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let mut pod = crate::ffi::SubmitFactsFfi::zeroed();
            unsafe { shekyl_submit_facts_rust_fill(&raw mut pod, seed) };
            assert_eq!(
                unsafe { shekyl_submit_facts_rust_check(&raw const pod, seed) },
                0
            );
            // A single-byte perturbation anywhere must fail the check.
            pod.root[31] ^= 0x01;
            assert_eq!(
                unsafe { shekyl_submit_facts_rust_check(&raw const pod, seed) },
                -1
            );
        }
    }
}
