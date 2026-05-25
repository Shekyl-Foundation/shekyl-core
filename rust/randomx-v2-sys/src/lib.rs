// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hand-written `extern "C"` bindings for the `external/randomx-v2`
//! C reference. Consumed exclusively by `shekyl-randomx-differential`
//! (the Phase 2g Rust/C differential test harness).
//!
//! See
//! [`docs/design/RANDOMX_V2_PHASE2G_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2G_PLAN.md)
//! §1.4, §1.7, §3.5 (R1-D2 close), §3.16 R4-D4 (signature pin),
//! §5.2, and §5.7 (drift-prevention discipline).
//!
//! # Why this crate exists
//!
//! Per R1-D2 option (c) close, the harness consumes the C reference
//! through a dedicated `*-sys`-shaped sub-crate that owns the
//! `extern "C"` declarations and (at C3 per §8.1 / §5.2.2) the
//! linker directives. Three reasons:
//!
//! 1. **Audit boundary.** All 7 declarations are in this one source
//!    file, audit-bounded against
//!    [`external/randomx-v2/src/randomx.h`](../../../external/randomx-v2/src/randomx.h)
//!    at the pinned fork commit (`aaafe71...`). Comparison against
//!    the C header is mechanical and one-time per fork-pin advance.
//!    Bindgen-generated declarations were rejected on auditability
//!    grounds per R1-D2 substrate-anchored rationale (generated code
//!    varies per bindgen version; for a 7-symbol surface the audit
//!    cost of hand-written declarations is one-time per fork-pin
//!    versus per-bindgen-version).
//! 2. **Sole-consumer discipline.** The Phase 2F crate-invariant
//!    grep gate
//!    ([`scripts/ci/check_randomx_crate_invariants.sh`](../../../scripts/ci/check_randomx_crate_invariants.sh))
//!    treats `extern "C"` declarations as a precedent-violation
//!    pattern in `shekyl-pow-randomx`. Localizing the FFI surface
//!    to this sub-crate keeps the verifier crate's Pattern C
//!    invariant intact while making the unsafe surface explicit
//!    here. T14 (§6.6) asserts this crate has exactly one consumer
//!    via `cargo metadata`.
//! 3. **Build-system isolation.** The `build.rs` (lands at C3 per
//!    §8.1; not yet present at C1) will emit
//!    `cargo:rustc-link-search` + `cargo:rustc-link-lib=static=randomx`
//!    directives gated on the `RANDOMX_V2_INSTALL_DIR` environment
//!    variable per R4-D3. The verifier crate gains no link surface.
//!
//! # Fork-pin coupling
//!
//! The 7-signature surface is pinned against
//! `external/randomx-v2/src/randomx.h` at fork commit
//! `aaafe71322df6602c21a5c72937ac284724ae561`. The
//! `[package.metadata.shekyl]` `fork-pin-coupled = true` +
//! `fork-pin-sha = "aaafe71..."` markers in `Cargo.toml` are the
//! audit-trail anchors; T15 (§6.7) asserts the metadata SHA
//! matches the current HEAD of `external/randomx-v2` at per-PR
//! cadence. Any advance of the fork pin requires re-verifying the
//! 7 declarations against the new pin's `randomx.h` (R1-D2
//! reopening criterion).
//!
//! # Safety
//!
//! All declared functions are implicitly `unsafe` to call (Rust
//! 2021 edition treats functions inside an `extern` block as
//! `unsafe fn`). Callers must observe the lifetime + null-pointer
//! contracts in
//! [`external/randomx-v2/src/randomx.h`](../../../external/randomx-v2/src/randomx.h):
//!
//! - [`randomx_alloc_cache`] and [`randomx_create_vm`] return NULL
//!   on allocation failure; callers must check before use.
//! - The pointer returned by [`randomx_get_cache_memory`] is owned
//!   by the cache; callers must NOT free it, and must not retain it
//!   past the matching [`randomx_release_cache`] call.
//! - [`randomx_destroy_vm`] does NOT release the cache; callers
//!   must release the cache separately via [`randomx_release_cache`].
//! - Light-mode VM construction (R4-D5 disposition): pass a non-NULL
//!   `cache` and a NULL `dataset` to [`randomx_create_vm`]. The
//!   harness is light-mode-only; dataset-related symbols are not
//!   declared here on purpose (declaring unused symbols invites a
//!   future caller to use them without re-auditing the scope-vs-
//!   fork-pin assumption per R1-D2).
//!
//! This crate does not wrap the FFI in safe abstractions; consumers
//! (`shekyl-randomx-differential`'s `c_oracle.rs` per §5.1.8) are
//! responsible for the safe wrappers.

#![deny(missing_docs)]

use std::os::raw::{c_int, c_void};

/// Opaque handle to a `randomx_cache` allocated by
/// [`randomx_alloc_cache`]. Zero-sized `_opaque: [u8; 0]` body
/// matches the established Shekyl FFI pattern (see
/// `rust/shekyl-daemon-rpc/src/ffi.rs` `CoreRpcHandle`) and avoids
/// implying a concrete size for an incomplete C type. Never
/// constructed or dereferenced by Rust code; only used through
/// `*mut RandomxCache` pointers returned by the C library.
#[repr(C)]
pub struct RandomxCache {
    _opaque: [u8; 0],
}

/// Opaque handle to a `randomx_vm` allocated by
/// [`randomx_create_vm`]. Zero-sized `_opaque: [u8; 0]` body
/// matches the established Shekyl FFI pattern (see
/// `rust/shekyl-daemon-rpc/src/ffi.rs` `CoreRpcHandle`) and avoids
/// implying a concrete size for an incomplete C type. Never
/// constructed or dereferenced by Rust code; only used through
/// `*mut RandomxVm` pointers returned by the C library.
#[repr(C)]
pub struct RandomxVm {
    _opaque: [u8; 0],
}

/// `randomx_flags` is a C `enum` with compiler-chosen integer
/// width; the type alias to [`c_int`] matches the C99 default of
/// `int`-sized enums on every platform the harness targets. The
/// harness uses [`RANDOMX_FLAG_DEFAULT`] for both cache and VM
/// allocation per R4-D5.
pub type RandomxFlags = c_int;

/// `RANDOMX_FLAG_DEFAULT = 0` per
/// [`external/randomx-v2/src/randomx.h`](../../../external/randomx-v2/src/randomx.h)'s
/// `randomx_flags` enum. Software-only execution: no JIT, no
/// large-pages, no AES-NI. Slowest path but deterministic across
/// platforms — required for the harness's byte-equality assertions
/// on heterogeneous runners (per R4-D5 cache-flag choice
/// rationale).
pub const RANDOMX_FLAG_DEFAULT: RandomxFlags = 0;

extern "C" {
    /// Allocate a `randomx_cache` instance. Returns NULL on
    /// allocation failure; callers must check before use. Caller
    /// releases via [`randomx_release_cache`].
    pub fn randomx_alloc_cache(flags: RandomxFlags) -> *mut RandomxCache;

    /// Initialize the cache from a seed (the RandomX "key"). `key`
    /// is a pointer to `key_size` bytes; the cache is filled from
    /// the seed via Argon2d-512 per `specs.md` §7.1. Must be called
    /// after [`randomx_alloc_cache`] and before
    /// [`randomx_create_vm`] with this cache.
    pub fn randomx_init_cache(cache: *mut RandomxCache, key: *const c_void, key_size: usize);

    /// Return a pointer to the cache's internal memory (the 256-MiB
    /// Argon2d-fill buffer). Used by §5.1.7 + R1-D14 for the
    /// SHA-256 cache-equivalence precondition: the harness streams
    /// `RANDOMX_CACHE_SIZE` bytes through a `Sha256` hasher and
    /// compares against the Rust subject's cache fingerprint
    /// computed via [`shekyl_pow_randomx::PreparedCache::cache_block_bytes_for_testing`]
    /// (gated on the `test-internals` feature per R5-D1). The
    /// pointer is owned by the cache; do not free, and do not
    /// retain past the matching [`randomx_release_cache`] call.
    pub fn randomx_get_cache_memory(cache: *mut RandomxCache) -> *mut c_void;

    /// Release a cache allocated via [`randomx_alloc_cache`].
    pub fn randomx_release_cache(cache: *mut RandomxCache);

    /// Create a VM bound to a cache. Light mode (R4-D5): pass a
    /// non-NULL `cache` and a NULL `dataset`. Returns NULL on
    /// allocation failure; callers must check before use.
    pub fn randomx_create_vm(
        flags: RandomxFlags,
        cache: *mut RandomxCache,
        dataset: *mut c_void,
    ) -> *mut RandomxVm;

    /// Destroy a VM created via [`randomx_create_vm`]. Does NOT
    /// release the cache; callers must release the cache separately
    /// via [`randomx_release_cache`].
    pub fn randomx_destroy_vm(machine: *mut RandomxVm);

    /// Compute one RandomX hash. `input` is a pointer to
    /// `input_size` bytes; `output` is a pointer to a 32-byte
    /// buffer that receives the hash. Equivalent at the byte level
    /// to `RandomxHash::calculate(rxvm, input).bytes` in the Rust
    /// port (the byte-equality assertion is the harness's
    /// correctness gate per T1 / T2).
    pub fn randomx_calculate_hash(
        machine: *mut RandomxVm,
        input: *const c_void,
        input_size: usize,
        output: *mut c_void,
    );
}
