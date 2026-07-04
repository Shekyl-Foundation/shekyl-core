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
/// - `bind_addr` must be a valid null-terminated C string, or null (returns null).
/// - The pointed-to `core_rpc_server` must remain alive for the lifetime of the
///   returned handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_start(
    rpc_server_ptr: *mut std::ffi::c_void,
    bind_addr: *const c_char,
    restricted: bool,
) -> *mut ShekylDaemonRpcHandle {
    if rpc_server_ptr.is_null() || bind_addr.is_null() {
        return std::ptr::null_mut();
    }

    let bind = match std::ffi::CStr::from_ptr(bind_addr).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return std::ptr::null_mut(),
    };

    let core = match crate::core::CoreRpc::from_raw(rpc_server_ptr) {
        Some(c) => std::sync::Arc::new(c),
        None => return std::ptr::null_mut(),
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("daemon-rpc")
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let config = crate::server::ServerConfig {
        bind_address: bind,
        restricted,
        ..Default::default()
    };

    // Bind synchronously so a failure (EADDRINUSE, bad address) is reported to
    // the caller as a null handle rather than logged-and-dropped inside the
    // spawned serve task. The runtime is dropped on the early return.
    let listener = match rt.block_on(crate::server::bind_listener(&config.bind_address)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("daemon-rpc bind failed on {}: {e}", config.bind_address);
            return std::ptr::null_mut();
        }
    };

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_for_server = shutdown.clone();

    rt.spawn(async move {
        if let Err(e) =
            crate::server::serve_with_listener(core, config, listener, shutdown_for_server).await
        {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });

    let handle = Box::new(ShekylDaemonRpcHandle {
        shutdown: std::sync::Arc::into_raw(shutdown),
        rt: Box::into_raw(Box::new(rt)) as *const _,
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

    if !handle.shutdown.is_null() {
        let notify = std::sync::Arc::from_raw(handle.shutdown);
        notify.notify_one();
    }

    if !handle.rt.is_null() {
        let rt = Box::from_raw(handle.rt as *mut tokio::runtime::Runtime);
        rt.shutdown_background();
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
        reserved: [0; 4],
        ref_height: submit_facts_field_value(seed, 4),
        root,
        fee_per_byte: submit_facts_field_value(seed, 6),
        fee_quantization_mask: submit_facts_field_value(seed, 7),
        weight_limit: submit_facts_field_value(seed, 8),
        chain_height: submit_facts_field_value(seed, 9),
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
        let values: Vec<u64> = (0..10).map(|f| submit_facts_field_value(seed, f)).collect();
        let mut deduped = values.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), values.len());
    }

    #[test]
    fn rust_fill_check_round_trips() {
        for seed in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
            let mut pod = crate::ffi::SubmitFactsFfi::zeroed();
            unsafe { shekyl_submit_facts_rust_fill(&mut pod, seed) };
            assert_eq!(unsafe { shekyl_submit_facts_rust_check(&pod, seed) }, 0);
            // A single-byte perturbation anywhere must fail the check.
            pod.root[31] ^= 0x01;
            assert_eq!(unsafe { shekyl_submit_facts_rust_check(&pod, seed) }, -1);
        }
    }
}
