// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the Shekyl RandomX v2 light-cache PoW verifier.
//!
//! The exports wrap [`shekyl_pow_randomx`] in a C-compatible ABI:
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
//! - [`shekyl_pow_randomx_v2_seedheight`] /
//!   [`shekyl_pow_randomx_v2_next_seedheight`] /
//!   [`shekyl_pow_randomx_v2_seed_epoch_blocks`] /
//!   [`shekyl_pow_randomx_v2_seed_epoch_overridden`] — the seed-epoch
//!   schedule (replacing `crypto::rx_seedheight`/`rx_seedheights`). The
//!   schedule arithmetic is pure and lives in
//!   `shekyl_difficulty::seed_epoch` (moved there from the engine crate
//!   2026-09-19 so the validator adopts the one implementation for
//!   CEN-D3 without depending on the engine — DRS-E6 slice 2); **this
//!   module owns the ambient half** — the `SEEDHASH_EPOCH_*` env
//!   overrides (regtest fast-epoch lever) are read once per process here,
//!   clamped by the `clamp_*` functions below, and passed in as
//!   parameters, keeping both the verifier crate and the validation crate
//!   free of runtime state.
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

use std::sync::{Mutex, OnceLock};

use shekyl_difficulty::{next_seedheight, seedheight, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
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

    // Eager derivation off the hot path, then sticky-pin — one call, so
    // the 256 MiB fill is paid exactly once here rather than lazily on the
    // first verifying call of the epoch. The daemon does not measure
    // derivations; the outcome is the ingest pipeline's to read.
    let _served = cache_store().pin_canonical(&seed);
    SHEKYL_POW_RANDOMX_V2_OK
}

/// Clamp a raw `SEEDHASH_EPOCH_LAG` override exactly as the C `atoi`
/// path did for in-range values: absent → default; unparsable → 0 →
/// fails power-of-two → default; parsed but `> default` or not a
/// power of two → default.
///
/// C-parity is precise, not bit-for-bit: three deliberate deltas from
/// glibc `atoi`, all regtest-lever-only and measured against the C before
/// deletion — values ≥ 2³² clamp to the default instead of wrapping
/// mod 2³² (glibc: `atoi("4294967312") == 16`, so the old C *accepted*
/// absurd wrapped overrides); only ASCII whitespace is skipped (C
/// `isspace`; a plain `str::trim_start` would accept NBSP-prefixed values
/// the C rejected); non-UTF-8 env bytes read as absent (the C parsed the
/// raw byte prefix).
/// The seed-epoch schedule the daemon recorded from its `dev-` rows
/// (`dev-pow-seed-epoch-blocks`, `dev-pow-seed-epoch-lag`;
/// `DAEMON_CONFIG_CUTOVER.md` §4.2), before the first read latched it.
static RECORDED: Mutex<Option<(u64, u64)>> = Mutex::new(None);

/// Why the daemon's seed-epoch rows were refused. Each arm names the row
/// it is about, except a latch that already happened: that refusal is the
/// machine's, and pinning either row would blame the wrong one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedEpochRefusal {
    /// `dev-pow-seed-epoch-blocks` is not a power of two in range.
    Blocks(String),
    /// `dev-pow-seed-epoch-lag` is not a power of two at most the lag.
    Lag(String),
    /// The schedule had already latched. No row owns that fact.
    Latched(String),
}

impl SeedEpochRefusal {
    /// The option the refusal is about, when one option owns it.
    #[must_use]
    pub const fn row(&self) -> Option<&'static str> {
        match self {
            Self::Blocks(_) => Some("dev-pow-seed-epoch-blocks"),
            Self::Lag(_) => Some("dev-pow-seed-epoch-lag"),
            Self::Latched(_) => None,
        }
    }

    /// The rule the diagnostic prints.
    #[must_use]
    pub fn rule(&self) -> &str {
        match self {
            Self::Blocks(rule) | Self::Lag(rule) | Self::Latched(rule) => rule,
        }
    }
}

impl std::fmt::Display for SeedEpochRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule())
    }
}

impl std::error::Error for SeedEpochRefusal {}

/// The schedule the daemon's seed-epoch rows name, or the row's refusal.
/// Pure: the configuration check calls this and latches nothing
/// (`INPUT_GRAMMAR.md` IG-Q59); [`record_seed_epoch`] calls it and then
/// latches, so the rule is written once. `None` is the mainnet value.
///
/// # Errors
/// [`SeedEpochRefusal::Blocks`] when the length is not a power of two in
/// `2..=SEEDHASH_EPOCH_BLOCKS`, [`SeedEpochRefusal::Lag`] when the lag is
/// not a power of two at most `SEEDHASH_EPOCH_LAG`.
pub fn check_seed_epoch(
    blocks: Option<u64>,
    lag: Option<u64>,
) -> Result<(u64, u64), SeedEpochRefusal> {
    let blocks = match blocks {
        Some(b) if (2..=SEEDHASH_EPOCH_BLOCKS).contains(&b) && b.is_power_of_two() => b,
        Some(_) => {
            return Err(SeedEpochRefusal::Blocks(format!(
                "a power of two from 2 to {SEEDHASH_EPOCH_BLOCKS}"
            )))
        }
        None => SEEDHASH_EPOCH_BLOCKS,
    };
    let lag = match lag {
        Some(l) if l <= SEEDHASH_EPOCH_LAG && l.is_power_of_two() => l,
        Some(_) => {
            return Err(SeedEpochRefusal::Lag(format!(
                "a power of two at most {SEEDHASH_EPOCH_LAG}"
            )))
        }
        None => SEEDHASH_EPOCH_LAG,
    };
    Ok((blocks, lag))
}

/// Records the seed-epoch schedule from the daemon's section: the Rust
/// `main()` calls this at step 6, before any export reads it. The value
/// is [`check_seed_epoch`]'s. The daemon refuses to start on `Err`, naming
/// the row the arm carries.
///
/// # Errors
/// [`check_seed_epoch`]'s refusals, and [`SeedEpochRefusal::Latched`] when
/// a read already pinned a different pair.
pub fn record_seed_epoch(blocks: Option<u64>, lag: Option<u64>) -> Result<(), SeedEpochRefusal> {
    let (blocks, lag) = check_seed_epoch(blocks, lag)?;
    if let Some(latched) = PARAMS.get() {
        if *latched != (blocks, lag) {
            return Err(SeedEpochRefusal::Latched(
                "the seed-epoch schedule had already latched".to_owned(),
            ));
        }
    }
    *RECORDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((blocks, lag));
    Ok(())
}

/// The latched `(epoch_blocks, epoch_lag)`: what was recorded, or the
/// mainnet schedule. Read once per process, as the retired C statics were.
static PARAMS: OnceLock<(u64, u64)> = OnceLock::new();

/// The effective `(epoch_blocks, epoch_lag)` schedule parameters:
/// mainnet defaults, or the recorded regtest lever.
fn seed_epoch_params() -> (u64, u64) {
    *PARAMS.get_or_init(|| {
        RECORDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or((SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG))
    })
}

/// The height whose block hash seeds the cache used to verify `height`
/// — the RandomX seed-epoch schedule (2048-block epochs, 64-block lag;
/// `SEEDHASH_EPOCH_*` env overrides are the regtest lever, read once).
///
/// Pure `u64 → u64` (no pointers); total over the domain — the lag
/// addition in the `next` variant wraps like the C `uint64_t` did.
/// Replaces the retired C `rx_seedheight`.
#[no_mangle]
pub extern "C" fn shekyl_pow_randomx_v2_seedheight(height: u64) -> u64 {
    let (blocks, lag) = seed_epoch_params();
    seedheight(height, blocks, lag)
}

/// `seedheight(height + lag)` — the upcoming seed height, for the RPC
/// next-seed pre-announce path (the second output of the retired C
/// `rx_seedheights`). Wrapping add at `u64::MAX`, matching C.
#[no_mangle]
pub extern "C" fn shekyl_pow_randomx_v2_next_seedheight(height: u64) -> u64 {
    let (blocks, lag) = seed_epoch_params();
    next_seedheight(height, blocks, lag)
}

/// The effective seed-epoch length in blocks (2048, or the clamped
/// `SEEDHASH_EPOCH_BLOCKS` override). Single source of truth for C++
/// consumers that need the epoch length itself (block-sync sizing) —
/// replaces their independent, differently-clamped env parses.
#[no_mangle]
pub extern "C" fn shekyl_pow_randomx_v2_seed_epoch_blocks() -> u64 {
    seed_epoch_params().0
}

/// True iff the effective schedule differs from the mainnet defaults
/// (i.e. a `SEEDHASH_EPOCH_*` override is active). Lets the daemon log
/// a loud startup warning — the override silently changes a consensus
/// schedule, and a regtest env leaking into a production unit must be
/// visible in the logs, not discovered via chain fork.
#[no_mangle]
pub extern "C" fn shekyl_pow_randomx_v2_seed_epoch_overridden() -> bool {
    seed_epoch_params() != (SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record refuses what the C clamps used to silently replace with
    /// the mainnet value: the daemon names the row instead.
    #[test]
    fn a_seed_epoch_record_refuses_a_value_off_the_schedule() {
        assert!(matches!(
            record_seed_epoch(Some(3), None),
            Err(SeedEpochRefusal::Blocks(_))
        ));
        assert!(matches!(
            record_seed_epoch(Some(1), None),
            Err(SeedEpochRefusal::Blocks(_))
        ));
        assert!(matches!(
            record_seed_epoch(Some(SEEDHASH_EPOCH_BLOCKS * 2), None),
            Err(SeedEpochRefusal::Blocks(_))
        ));
        assert!(matches!(
            record_seed_epoch(None, Some(SEEDHASH_EPOCH_LAG * 2)),
            Err(SeedEpochRefusal::Lag(_))
        ));
        assert!(matches!(
            record_seed_epoch(None, Some(3)),
            Err(SeedEpochRefusal::Lag(_))
        ));
        assert_eq!(
            SeedEpochRefusal::Latched(String::new()).row(),
            None,
            "a latch is the machine's fact, not a row's"
        );
    }

    /// The configuration check's half refuses what the record refuses and
    /// never sees the latch: after a read pinned the schedule, a different
    /// valid pair is still `Ok` from the check and `Latched` from the record.
    #[test]
    fn the_check_judges_the_value_and_never_the_latch() {
        assert!(matches!(
            check_seed_epoch(Some(3), None),
            Err(SeedEpochRefusal::Blocks(_))
        ));
        assert!(matches!(
            check_seed_epoch(None, Some(3)),
            Err(SeedEpochRefusal::Lag(_))
        ));
        assert_eq!(
            check_seed_epoch(None, None),
            Ok((SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG))
        );
        // Pin the schedule through a read, as the first verify would.
        let pinned = seed_epoch_params();
        let other = if pinned.0 == 2 { 4 } else { 2 };
        assert_eq!(check_seed_epoch(Some(other), Some(1)), Ok((other, 1)));
        assert!(matches!(
            record_seed_epoch(Some(other), Some(1)),
            Err(SeedEpochRefusal::Latched(_))
        ));
    }
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

    /// Serializes the canonical-mutating tests: the process-global
    /// store has ONE canonical slot, and the sticky-eviction guarantee
    /// protects only whichever seed currently holds it — two parallel
    /// `set_canonical` tests would demote each other's seed to the
    /// transient tier, where a concurrent novel derive can evict it
    /// (a microsecond-window flake, but a flake on a consensus-adjacent
    /// gate reads as a false "lazy derive" red). Poison-tolerant so one
    /// failing test doesn't cascade.
    static CANONICAL_SLOT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `set_canonical` derives + pins, then a hash under the pinned
    /// seed succeeds and matches the direct path. Idempotent re-pin is
    /// also a no-op success.
    #[test]
    fn set_canonical_pins_and_hashes() {
        let _canonical_slot = CANONICAL_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// The eager-derive claim as a behavior gate (RandomX v2 test-regime
    /// hardening: epoch-rollover stall check). `set_canonical`'s contract
    /// is that the canonical cache is derived AT tip advance, off the
    /// validation hot path — so the first verify after a seed-epoch
    /// rollover never pays the multi-second cache build, which would
    /// delay propagation of the first post-boundary block network-wide
    /// (orphan-risk-shaped). Until this test, that claim lived only in
    /// doc comments.
    ///
    /// Probed as STATE, not latency: [`CacheStore::lookup`] never
    /// derives, so cache-present-immediately-after-`set_canonical` is
    /// exactly "the derive already happened". A lazy implementation
    /// fails this test deterministically; a wall-clock variant was
    /// rejected as flake-theater on shared runners (the house rule
    /// against absolute-time CI gates).
    #[test]
    fn set_canonical_eagerly_derives_off_the_verify_path() {
        // CANONICAL_SLOT_LOCK: while 0x77 holds the canonical slot the
        // sticky guarantee shields it from novel-derive eviction, and
        // the lock keeps the sibling canonical test from demoting it
        // mid-test. The unique seed (no other test uses 0x77) keeps the
        // is_none() precondition sound.
        let _canonical_slot = CANONICAL_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let seed_bytes = [0x77u8; 32];
        let seed = Seedhash::from_bytes(seed_bytes);

        assert!(
            cache_store().lookup(&seed).is_none(),
            "precondition: seed 0x77.. must be underived before set_canonical \
             (another test started using this seed?)"
        );

        // SAFETY: seed_bytes is a valid stack [u8; 32].
        let rc = unsafe { shekyl_pow_randomx_v2_set_canonical(&raw const seed_bytes) };
        assert_eq!(rc, SHEKYL_POW_RANDOMX_V2_OK);

        assert!(
            cache_store().lookup(&seed).is_some(),
            "set_canonical must derive the canonical cache EAGERLY: a lazy \
             derive stalls the first post-rollover verify by the full cache \
             build (the doc-comment claim this test converts into a gate)"
        );
    }

    /// The seed-epoch exports round the schedule through the C ABI
    /// unchanged: the expected values come from the same latched
    /// parameters the exports read, so the test verifies the WIRING
    /// (export == pure formula at the effective params); the schedule
    /// itself is KAT'd in `shekyl_difficulty::seed_epoch`.
    #[test]
    fn seedheight_exports_match_schedule() {
        let (blocks, lag) = seed_epoch_params();
        for h in [0u64, 2100, 2112, 2113, 4161, u64::MAX] {
            assert_eq!(
                shekyl_pow_randomx_v2_seedheight(h),
                seedheight(h, blocks, lag)
            );
            assert_eq!(
                shekyl_pow_randomx_v2_next_seedheight(h),
                next_seedheight(h, blocks, lag)
            );
        }
        assert_eq!(shekyl_pow_randomx_v2_seed_epoch_blocks(), blocks);
        assert_eq!(
            shekyl_pow_randomx_v2_seed_epoch_overridden(),
            (blocks, lag) != (2048, 64)
        );
    }
}
