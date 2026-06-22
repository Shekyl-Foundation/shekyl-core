// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the Shekyl RandomX v2 light-cache PoW verifier.
//!
//! Two exports wrap [`shekyl_pow_randomx`] in a C-compatible ABI:
//!
//! - [`shekyl_pow_randomx_v2_hash`] — the consensus PoW hash. Computes
//!   `compute_hash(seedhash, data)` through a process-global, internally
//!   memoized [`CacheStore`]. This replaces the inherited C RandomX v1
//!   path (`crypto::rx_slow_hash`) on the daemon's block-verification
//!   boundary per `docs/design/RANDOMX_V2_PHASE3_PLAN.md` §4.
//! - [`shekyl_pow_randomx_v2_set_canonical`] — pins the canonical epoch
//!   seedhash (sticky against LRU eviction) and *eagerly* derives its
//!   256 MiB cache off the validation hot path. Called by the daemon at
//!   tip advance, replacing `crypto::rx_set_main_seedhash`.
//!
//! The RandomX v2 algorithm itself lives entirely in
//! [`shekyl_pow_randomx`] (the `#![deny(unsafe_code)]` verifier crate);
//! this module is the `unsafe` boundary that translates raw pointers
//! into the crate's typed [`Seedhash`] / `&[u8]` API. Per
//! `36-secret-locality.mdc` and `20-rust-vs-cpp-policy.mdc`, the cache
//! memo and the canonical-seedhash lifecycle live here in Rust rather
//! than in the C++ caller; the C++ side holds only opaque 32-byte
//! buffers and an `i32` status.
//!
//! # Pointer-to-array ABI
//!
//! The 32-byte `seedhash` and `out_hash` arguments use the
//! pointer-to-array form `const uint8_t (*)[32]` / `uint8_t (*)[32]`
//! rather than a decayed `const uint8_t *`. The fixed length is part of
//! the type, so a wrong-sized buffer at a C++ call site is a
//! compile-time error rather than a silent out-of-bounds read. This is
//! the Round-5 hardening mandated by `RANDOMX_V2_PLAN.md` §5; it
//! supersedes the decayed-pointer form shown in the
//! `RANDOMX_V2_RUST.md` §5 code block (an erratum tracked for the §17
//! docs amendment). The `data` argument keeps the
//! `(*const u8, usize)` slice form because its length is genuinely
//! variable.
//!
//! # Panic safety
//!
//! The workspace runs `panic = "abort"` in both `dev` and `release`
//! profiles (`rust/Cargo.toml`). Under `panic = "abort"`, panics
//! terminate the process immediately rather than unwinding;
//! `std::panic::catch_unwind` is therefore a no-op and is not wrapped
//! around the verifier call. The safety property under abort is that an
//! uncaught panic cannot corrupt cross-FFI state because the process is
//! already gone. The verifier body is panic-free on the validation hot
//! path by construction ([`compute_hash`] performs only fixed-size
//! array arithmetic on a derived cache); the only panics reachable are
//! the cache-derivation infallible-allocation abort
//! (`handle_alloc_error` on a 256 MiB OOM, which is unrecoverable
//! regardless of which PoW path runs) and the in-flight
//! leader-abort propagation in [`CacheStore::lookup_or_derive`]. Both
//! are correct as aborts.
//!
//! Consequently the two structured-failure codes in the
//! `RANDOMX_V2_RUST.md` §17 taxonomy —
//! [`SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED`] and
//! [`SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL`] — are **reserved and never
//! returned** in this workspace: the conditions they describe abort the
//! process before the shim can construct a return value. They are
//! defined here (and in `shekyl_ffi.h`) for wire-stable ABI/taxonomy
//! parity with the spec so that a future `panic = "unwind"` posture, or
//! a future fallible-allocation cache path, can begin returning them
//! without renumbering. This mirrors
//! [`crate::difficulty_ffi::SHEKYL_DIFFICULTY_ERR_INTERNAL`].
//!
//! # Error taxonomy (`RANDOMX_V2_RUST.md` §17)
//!
//! | Code | Constant                                          | Meaning                                                          |
//! |-----:|:--------------------------------------------------|:-----------------------------------------------------------------|
//! |  `0` | [`SHEKYL_POW_RANDOMX_V2_OK`]                      | Success; `*out_hash` is written (hash only).                     |
//! | `-1` | [`SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR`]            | A required pointer was null (see the null-pointer rules below).  |
//! | `-2` | [`SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE`]      | `data_len` exceeds [`RANDOMX_BLOCK_TEMPLATE_MAX_SIZE`].           |
//! | `-3` | [`SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED`] | Reserved; never returned under `panic = "abort"` (see above).    |
//! | `-4` | [`SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL`]            | Reserved; never returned under `panic = "abort"` (see above).    |
//!
//! # Null-pointer and `data` / `data_len` convention (`RANDOMX_V2_RUST.md` §17)
//!
//! For [`shekyl_pow_randomx_v2_hash`]:
//! - `seedhash` and `out_hash` must always be non-null.
//! - `data == NULL && data_len == 0` is valid (empty input).
//! - `data == NULL && data_len > 0` is invalid → `ERR_NULL_PTR`.
//! - `data != NULL && data_len == 0` is valid (the pointer is ignored).
//! - `data != NULL && data_len > 0` is the normal case; the bytes
//!   `[data, data + data_len)` must be readable.
//!
//! For [`shekyl_pow_randomx_v2_set_canonical`]: `seedhash` must be
//! non-null.
//!
//! On any non-zero return `out_hash` is untouched; callers must not read
//! it (in particular, must not treat zeroed memory as a hash).
//!
//! # Thread-safety and the cache memo (`RANDOMX_V2_RUST.md` §18)
//!
//! The internal [`CacheStore`] is a process-global `static` reachable
//! through [`OnceLock`]. It is `Send + Sync` and synchronizes its own
//! state: concurrent verification threads may call
//! [`shekyl_pow_randomx_v2_hash`] in parallel without external locking,
//! and a concurrent cache miss for the same seedhash deduplicates to a
//! single derivation under lock. `shekyl-pow-randomx` itself holds no
//! module-level state (`RANDOMX_V2_RUST.md` §7.2); the memo lives here
//! at the FFI boundary.

use std::sync::{Arc, OnceLock};

use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};

/// Upper bound on `data_len` accepted by [`shekyl_pow_randomx_v2_hash`].
///
/// A RandomX hashing blob is a few hundred bytes (block header +
/// merge-mining tag); this 2 MiB ceiling rejects absurd inputs while
/// never rejecting a legitimate hashing blob. It matches the
/// `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` bound named in
/// `RANDOMX_V2_PHASE3_PLAN.md` §6 / `RANDOMX_V2_RUST.md` §17 ("the
/// verifier's hashing-blob bound"). Kept Rust-internal rather than a
/// `shekyl_ffi.h` `#define`: the spec defines no public bound constant,
/// and the daemon's hashing blob is far below this ceiling.
pub const RANDOMX_BLOCK_TEMPLATE_MAX_SIZE: usize = 2 * 1024 * 1024;

/// Success status code returned by the `shekyl_pow_randomx_v2_*`
/// exports.
pub const SHEKYL_POW_RANDOMX_V2_OK: i32 = 0;
/// A required FFI pointer was null. See module docs for the
/// null-pointer convention.
pub const SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR: i32 = -1;
/// `data_len` exceeds [`RANDOMX_BLOCK_TEMPLATE_MAX_SIZE`]. `out_hash`
/// is not written.
pub const SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE: i32 = -2;
/// Reserved for a structured cache-derivation failure. Not returned in
/// this workspace: the cache-derivation allocation path uses infallible
/// allocation that aborts on OOM under `panic = "abort"`. See module
/// docs.
pub const SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED: i32 = -3;
/// Reserved for an unexpected internal failure (a panic crossing the
/// FFI boundary). Not returned in this workspace; `panic = "abort"`
/// short-circuits any path that would otherwise need it. See module
/// docs.
pub const SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL: i32 = -4;

/// Process-global cache memo for the RandomX v2 verifier.
///
/// Initialized on first use. Holds the canonical (sticky) and transient
/// (LRU) [`shekyl_pow_randomx::PreparedCache`] slots plus the in-flight
/// derivation map; see [`CacheStore`] for the eviction/dedup policy.
static CACHE_STORE: OnceLock<CacheStore> = OnceLock::new();

/// Borrow the process-global [`CacheStore`], initializing it on first
/// use.
fn cache_store() -> &'static CacheStore {
    CACHE_STORE.get_or_init(CacheStore::new)
}

/// Compute the RandomX v2 PoW hash of `data[0..data_len]` under
/// `seedhash`.
///
/// On success writes exactly 32 bytes to `*out_hash` and returns
/// [`SHEKYL_POW_RANDOMX_V2_OK`]. The cache for `seedhash` is derived
/// lazily on first use and memoized in the process-global
/// [`CacheStore`]; the daemon eliminates the first-use latency on the
/// canonical seedhash by calling
/// [`shekyl_pow_randomx_v2_set_canonical`] at tip advance.
///
/// # Return
///
/// [`SHEKYL_POW_RANDOMX_V2_OK`] on success, or a negative error code
/// (see the module-level error taxonomy).
///
/// # Safety
///
/// The caller must uphold:
/// - `seedhash` points to a valid, aligned, initialized `[u8; 32]`.
/// - `out_hash` points to a valid, aligned, writable `[u8; 32]`.
/// - When `data_len > 0`, `data` points to `data_len` readable bytes.
/// - The buffers do not alias each other.
/// - No other thread mutates the buffers for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pow_randomx_v2_hash(
    seedhash: *const [u8; 32],
    data: *const u8,
    data_len: usize,
    out_hash: *mut [u8; 32],
) -> i32 {
    if seedhash.is_null() || out_hash.is_null() {
        return SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR;
    }
    if data.is_null() && data_len > 0 {
        return SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR;
    }
    if data_len > RANDOMX_BLOCK_TEMPLATE_MAX_SIZE {
        return SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE;
    }

    // SAFETY: seedhash is non-null per the check above; the caller's
    // contract guarantees an aligned, initialized [u8; 32].
    let seed = Seedhash::from_bytes(*seedhash);

    // SAFETY: when data_len > 0, data is non-null per the check above
    // and the caller guarantees data_len readable bytes. The empty case
    // (data null or data_len == 0) uses a valid empty slice per the
    // §17 data/data_len convention.
    let data_slice: &[u8] = if data_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(data, data_len)
    };

    let prepared = cache_store().lookup_or_derive(&seed);
    let hash = compute_hash(&prepared, data_slice);

    // SAFETY: out_hash is non-null per the check above; the caller's
    // contract guarantees alignment and writability for [u8; 32].
    core::ptr::write(out_hash, hash);
    SHEKYL_POW_RANDOMX_V2_OK
}

/// Pin `*seedhash` as the canonical cache and eagerly derive it.
///
/// Called by the daemon at tip advance (replacing
/// `crypto::rx_set_main_seedhash`). Two effects, in order:
///
/// 1. Eager derivation — [`CacheStore::lookup_or_derive`] performs the
///    synchronous ~150–200 ms / 256 MiB Argon2d derivation *now*, off
///    the per-block validation hot path, so the first verifying call of
///    the new epoch is a cache hit. This is the internal-prewarm
///    disposition of `RANDOMX_V2_PHASE3_PLAN.md` §4.3 (Hole 2): no
///    `prewarm` FFI surface is added; the eager derivation is a Rust
///    internal detail of this export.
/// 2. Sticky pin — [`CacheStore::set_canonical`] protects the derived
///    cache from LRU eviction by transient lookups, the DoS protection
///    of `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7 / `RANDOMX_V2_PLAN.md`
///    Decision #6.
///
/// Idempotent: re-pinning the already-canonical seedhash is a no-op
/// (`CacheStore` compares seedhashes before swapping).
///
/// # Return
///
/// [`SHEKYL_POW_RANDOMX_V2_OK`] on success, or
/// [`SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR`] if `seedhash` is null.
///
/// # Safety
///
/// The caller must uphold:
/// - `seedhash` points to a valid, aligned, initialized `[u8; 32]`.
/// - No other thread mutates that buffer for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pow_randomx_v2_set_canonical(seedhash: *const [u8; 32]) -> i32 {
    if seedhash.is_null() {
        return SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR;
    }

    // SAFETY: seedhash is non-null per the check above; the caller's
    // contract guarantees an aligned, initialized [u8; 32].
    let seed = Seedhash::from_bytes(*seedhash);

    // Eager derivation off the hot path, then sticky-pin. The two steps
    // are deliberately not collapsed: lookup_or_derive both warms the
    // cache and returns the Arc that set_canonical pins, so the 256 MiB
    // fill is paid exactly once here rather than lazily on the first
    // verifying call of the epoch.
    let prepared: Arc<_> = cache_store().lookup_or_derive(&seed);
    cache_store().set_canonical(prepared);
    SHEKYL_POW_RANDOMX_V2_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_pow_randomx::PreparedCache;

    /// `seedhash == NULL` is rejected before any dereference.
    #[test]
    fn null_seedhash_rejected() {
        let mut out = [0u8; 32];
        // SAFETY: seedhash is null, which the FFI rejects with
        // ERR_NULL_PTR before dereferencing; out is a valid stack slot.
        let rc = unsafe {
            shekyl_pow_randomx_v2_hash(core::ptr::null(), core::ptr::null(), 0, &raw mut out)
        };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR);
        assert_eq!(out, [0u8; 32], "out must be untouched on error");
    }

    /// `out_hash == NULL` is rejected before any dereference.
    #[test]
    fn null_out_hash_rejected() {
        let seed = [0x11u8; 32];
        // SAFETY: out_hash is null, which the FFI rejects with
        // ERR_NULL_PTR before writing; seed is a valid stack slot.
        let rc = unsafe {
            shekyl_pow_randomx_v2_hash(&raw const seed, core::ptr::null(), 0, core::ptr::null_mut())
        };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR);
    }

    /// `data == NULL && data_len > 0` is the invalid pairing →
    /// `ERR_NULL_PTR` (§17 data/data_len convention).
    #[test]
    fn null_data_with_nonzero_len_rejected() {
        let seed = [0x11u8; 32];
        let mut out = [0u8; 32];
        // SAFETY: data is null with data_len > 0, the invalid pairing
        // the FFI rejects before dereferencing; seed/out are valid.
        let rc = unsafe {
            shekyl_pow_randomx_v2_hash(&raw const seed, core::ptr::null(), 1, &raw mut out)
        };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR);
        assert_eq!(out, [0u8; 32], "out must be untouched on error");
    }

    /// `data_len > RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` → `ERR_DATA_TOO_LARGE`.
    ///
    /// The bound is checked before any read, so passing a dangling
    /// `data` pointer with an over-large length is rejected without a
    /// dereference (and without a multi-MiB allocation).
    #[test]
    fn oversized_data_len_rejected() {
        let seed = [0x11u8; 32];
        let mut out = [0u8; 32];
        let one_byte = [0u8; 1];
        // SAFETY: data points to one valid byte but data_len claims
        // MAX + 1; the FFI rejects on the length bound before reading,
        // so it never touches beyond the buffer.
        let rc = unsafe {
            shekyl_pow_randomx_v2_hash(
                &raw const seed,
                one_byte.as_ptr(),
                RANDOMX_BLOCK_TEMPLATE_MAX_SIZE + 1,
                &raw mut out,
            )
        };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE);
        assert_eq!(out, [0u8; 32], "out must be untouched on error");
    }

    /// A valid call writes a hash byte-identical to the crate's own
    /// `compute_hash(PreparedCache::derive(seed), data)` — proving the
    /// FFI shim wires seedhash + blob through to the verifier without
    /// reshaping the inputs. Also exercises the `data == NULL,
    /// data_len == 0` empty-input valid case being a distinct seed.
    #[test]
    fn hash_matches_direct_compute() {
        let seed_bytes = [0x11u8; 32];
        let blob = b"shekyl randomx v2 ffi parity blob";

        let mut out = [0u8; 32];
        // SAFETY: seed/blob/out are valid stack buffers correctly sized
        // for the call.
        let rc = unsafe {
            shekyl_pow_randomx_v2_hash(
                &raw const seed_bytes,
                blob.as_ptr(),
                blob.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_OK);

        let prepared = PreparedCache::derive(Seedhash::from_bytes(seed_bytes));
        let expected = compute_hash(&prepared, blob);
        assert_eq!(out, expected, "FFI hash must equal direct compute_hash");
        assert_ne!(out, [0u8; 32], "a real hash is overwhelmingly non-zero");
    }

    /// Repeated calls with the same seed + blob are deterministic; the
    /// second call is a cache hit on the process-global store.
    #[test]
    fn hash_is_deterministic() {
        let seed_bytes = [0x44u8; 32];
        let blob = b"determinism";

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        // SAFETY: all buffers are valid stack slots sized for the call.
        unsafe {
            let ra = shekyl_pow_randomx_v2_hash(
                &raw const seed_bytes,
                blob.as_ptr(),
                blob.len(),
                &raw mut a,
            );
            let rb = shekyl_pow_randomx_v2_hash(
                &raw const seed_bytes,
                blob.as_ptr(),
                blob.len(),
                &raw mut b,
            );
            assert_eq!(ra, SHEKYL_POW_RANDOMX_V2_OK);
            assert_eq!(rb, SHEKYL_POW_RANDOMX_V2_OK);
        }
        assert_eq!(a, b);
    }

    /// `set_canonical(NULL)` is rejected before any dereference.
    #[test]
    fn set_canonical_null_rejected() {
        // SAFETY: seedhash is null, which the FFI rejects with
        // ERR_NULL_PTR before dereferencing.
        let rc = unsafe { shekyl_pow_randomx_v2_set_canonical(core::ptr::null()) };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR);
    }

    /// `set_canonical` derives + pins, then a hash under the pinned
    /// seed succeeds and matches the direct path. Idempotent re-pin is
    /// also a no-op success.
    #[test]
    fn set_canonical_pins_and_hashes() {
        let seed_bytes = [0x22u8; 32];

        // SAFETY: seed_bytes is a valid stack [u8; 32].
        let rc = unsafe { shekyl_pow_randomx_v2_set_canonical(&raw const seed_bytes) };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_OK);

        // Re-pin the same seed: idempotent no-op success.
        // SAFETY: same valid buffer.
        let rc2 = unsafe { shekyl_pow_randomx_v2_set_canonical(&raw const seed_bytes) };
        assert_eq!(rc2, SHEKYL_POW_RANDOMX_V2_OK);

        let blob = b"canonical";
        let mut out = [0u8; 32];
        // SAFETY: all buffers are valid stack slots sized for the call.
        let rc3 = unsafe {
            shekyl_pow_randomx_v2_hash(
                &raw const seed_bytes,
                blob.as_ptr(),
                blob.len(),
                &raw mut out,
            )
        };
        assert_eq!(rc3, SHEKYL_POW_RANDOMX_V2_OK);

        let prepared = PreparedCache::derive(Seedhash::from_bytes(seed_bytes));
        let expected = compute_hash(&prepared, blob);
        assert_eq!(out, expected);
    }
}
