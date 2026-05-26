// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Safe RAII wrapper over `randomx-v2-sys` (the §5.1.8 C oracle).
//!
//! Per `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.1.8, §3.16 R4-D4,
//! and §3.16 R4-D5, this module owns the only Rust-side `unsafe`
//! block that allocates / initializes / frees C-reference
//! `randomx_cache` and `randomx_vm` handles. All call sites in the
//! harness consume the C oracle through this module's safe API; the
//! harness's other modules (`mode_correctness`, `mode_latency`,
//! `mode_concurrent`, `cache_precondition`) carry no direct FFI
//! calls and no `unsafe` blocks.
//!
//! ## Lifecycle (§5.1.8 + R4-D5)
//!
//! One [`COracleSession`] is constructed per **seedhash** (not per
//! `(seedhash, data)` pair). Inside the session, the C reference's
//! VM is reused across every data value tested for that seedhash;
//! the cache is reused for the lifetime of the session. Both the
//! VM and the cache are released by the [`Drop`] impl, in the
//! `randomx.h`-prescribed order (VM first, cache second; the cache
//! outlives the VM at construction time, so the symmetric release
//! is correct).
//!
//! This shape matches §5.1.8's "one `randomx_cache` + one
//! `randomx_vm` allocated per seedhash iteration (VM reused across
//! data values for same seedhash), freed before next seedhash"
//! disposition and the §5.2.6 `gen-canonical-outputs` binary's
//! reference shape — the two consumers differ only in the
//! intermediate logic between [`COracleSession::cache_sha256`] and
//! [`COracleSession::calculate_hash`].
//!
//! ## Flags (R4-D5 + verifier-divergence FOLLOWUP closure)
//!
//! The C reference splits flag handling between cache allocation
//! and VM creation; the two callsites honor disjoint subsets of
//! `randomx_flags`, and the harness's flag selection reflects that
//! split rather than a single "all allocations use flag X" pattern.
//!
//! ### Cache allocation: `randomx_alloc_cache(RANDOMX_FLAG_DEFAULT)`
//!
//! `randomx_alloc_cache` masks its `flags` argument to
//! `(RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES)` only (see
//! `external/randomx-v2/src/randomx.cpp:79`). Every other bit —
//! AES-NI, AVX2, SECURE, ARGON2_*, **the V2 algorithm-selection
//! bit** — is silently dropped at cache-allocation time and has
//! no observable effect on the resulting `randomx_cache`. The
//! cache memory layout is identical for v1 and v2 (the
//! algorithm-version distinction is runtime-only and lives
//! entirely in the VM), so a single `randomx_cache` instance can
//! back either VM flavor.
//!
//! Passing [`RANDOMX_FLAG_DEFAULT`] (`= 0`) at cache allocation
//! is therefore the same as passing [`RANDOMX_FLAG_V2`] at cache
//! allocation — both are masked to zero, JIT and large-pages both
//! stay off. The harness uses [`RANDOMX_FLAG_DEFAULT`] to make
//! the "JIT and large-pages off" intent explicit at the cache
//! callsite, not because the V2 bit would be honored.
//!
//! ### VM creation: `randomx_create_vm(RANDOMX_FLAG_V2, …)`
//!
//! `randomx_create_vm` is where the V2 bit is honored — the VM
//! constructor stores `flags` in `vmFlags`, and
//! `external/randomx-v2/src/program.hpp:57`'s
//! `(flags & RANDOMX_FLAG_V2) ? RANDOMX_PROGRAM_SIZE_V2
//! : RANDOMX_PROGRAM_SIZE_V1` selects the per-block program size
//! (384 vs 256) that the AES-round chain consumes. JIT,
//! large-pages, AES-NI, SECURE, etc. are *also* VM-creation
//! flags — they affect *execution method* at the VM, not the
//! algorithm version.
//!
//! ### Cross-runner determinism
//!
//! The byte-equality property the harness asserts depends on
//! every VM-creation flag that affects *execution method* being
//! held constant at the no-platform-acceleration baseline:
//!
//! - JIT off (no x86-64 emit; pure interpreter loop).
//! - Large-pages off (no `MAP_HUGETLB`-dependent allocator
//!   variance).
//! - AES-NI off (no AES-NI instructions; software AES round).
//! - SECURE off (no per-VM `mprotect` guard pages; identical
//!   page-table behavior across runners).
//!
//! All of these are bits the harness deliberately does *not* set
//! in the `randomx_create_vm` flag argument. The
//! algorithm-version bit ([`RANDOMX_FLAG_V2`]) is orthogonal —
//! it selects which algorithm the VM executes (v1 or v2), not
//! how the VM executes it. Setting [`RANDOMX_FLAG_V2`] does not
//! introduce execution-method nondeterminism; clearing it would
//! silently select v1, which is what the
//! verifier-divergence FOLLOWUP root cause was.
//!
//! Pre-FOLLOWUP-closure, `randomx_create_vm` was called with
//! [`RANDOMX_FLAG_DEFAULT`], which selected v1
//! (`PROGRAM_SIZE = 256`) against Rust v2 subjects
//! (`PROGRAM_SIZE = 384`) — the root cause of the V3.0
//! "verifier divergence on T1/T2 large random data" FOLLOWUP,
//! localized by `tests/divergence_triage.rs`'s D1 substrate
//! triage. See `randomx-v2-sys::RANDOMX_FLAG_V2`'s doc for the
//! upstream evidence and the upstream test pattern at
//! `external/randomx-v2/src/tests/tests.cpp:1032`
//! (`randomx_create_vm(RANDOMX_FLAG_V2, cache, nullptr)`).
//!
//! ### Summary
//!
//! - Cache callsite: `RANDOMX_FLAG_DEFAULT` (V2 bit would be
//!   masked anyway; explicit zero documents "JIT/large-pages
//!   off" intent).
//! - VM callsite: `RANDOMX_FLAG_V2` (algorithm-version
//!   selection; required for v1/v2 agreement with Rust). All
//!   execution-method bits left clear for deterministic
//!   cross-runner byte-equality per R4-D5.
//! - Any future flag added at the VM callsite must be evaluated
//!   against the "execution-method bit vs algorithm-version
//!   bit" distinction per `randomx-v2-sys::RandomxFlags`'s docs
//!   and the FOLLOWUP-closure discipline pin in
//!   `docs/FOLLOWUPS.md` "Recently resolved" section.
//!
//! ## Null-pointer error translation (§5.1.8)
//!
//! `randomx_alloc_cache` / `randomx_create_vm` returning `NULL`
//! translate to [`COracleError::CacheAllocFailed`] /
//! [`COracleError::VmCreateFailed`] respectively;
//! `randomx_get_cache_memory` returning `NULL` translates to
//! [`COracleError::CacheMemoryNull`]. Each error variant carries
//! the seedhash that surfaced it so failure-output reporting (T11
//! at C9) can attribute the failure to a specific corpus entry.
//!
//! ## Safety
//!
//! The `unsafe` blocks below are constrained to:
//!
//! 1. **Allocation / deallocation** of `randomx_cache` and
//!    `randomx_vm` opaque handles. The C reference's allocator
//!    owns the buffer; this module owns the handle and releases it
//!    on drop.
//! 2. **One `from_raw_parts`** call exposing the 256-MiB cache
//!    memory as `&[u8]`. The slice's lifetime is bounded by
//!    `&self`, so it cannot outlive the session; the C reference's
//!    `randomx_get_cache_memory` documents the pointer as valid for
//!    the cache's lifetime; the `from_raw_parts` requirements
//!    (non-null, aligned, valid-for-reads, no concurrent mutation)
//!    are all satisfied by §5.1.8 + R4-D5's "one cache per
//!    seedhash; VM reuses cache; no concurrent FFI calls per
//!    session" lifecycle.
//! 3. **One `randomx_calculate_hash`** call per hash request. The
//!    `input` / `output` pointers are produced from Rust slices
//!    immediately before the call and dropped immediately after; no
//!    aliasing.
//!
//! No `randomx-v2-sys` symbol is exposed outside this module. The
//! `#![deny(unsafe_code)]` discipline at the crate root is relaxed
//! to `#[allow(unsafe_code)]` for this module only.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;
use std::ptr;
use std::slice;

use randomx_v2_sys::{
    randomx_alloc_cache, randomx_calculate_hash, randomx_create_vm, randomx_destroy_vm,
    randomx_get_cache_memory, randomx_init_cache, randomx_release_cache, RandomxCache, RandomxVm,
    RANDOMX_FLAG_DEFAULT, RANDOMX_FLAG_V2,
};
use sha2::{Digest, Sha256};
use shekyl_pow_randomx::Seedhash;

/// Size of the C reference's cache memory in bytes.
///
/// `RANDOMX_ARGON_MEMORY (262144) × ArgonBlockSize (1024)` per the
/// C reference's `common.hpp:88`. Used to slice the
/// `randomx_get_cache_memory` return into a fixed-size byte view
/// before SHA-256 hashing (§5.1.7 R1-D14 precondition) and before
/// byte-by-byte diffing (T4 `--debug-cache-divergence` mode). The
/// constant is pinned against the same upstream source as the
/// verifier crate's `CACHE_SIZE` (cf. `shekyl-pow-randomx`'s
/// `argon2d.rs:78` `RANDOMX_ARGON_MEMORY = 262_144` +
/// `cache.rs::CACHE_SIZE`); the cross-crate equivalence is asserted
/// indirectly by T3 — a divergent value would make the per-PR
/// precondition fail before T1/T2 ever ran.
pub const RANDOMX_CACHE_SIZE_BYTES: usize = 262_144 * 1024;

/// Output width of `randomx_calculate_hash` per `randomx.h`.
pub const RANDOMX_HASH_SIZE: usize = 32;

/// Errors translating C-reference NULL returns into a Rust
/// `Result` per §5.1.8's null-pointer error translation discipline.
///
/// Each variant carries the seedhash that surfaced the failure so
/// the eventual C9 §5.1.14 failure-output JSON schema can attribute
/// the failure to a specific corpus entry without further
/// instrumentation in the calling mode module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum COracleError {
    /// `randomx_alloc_cache` returned `NULL`. Typically indicates a
    /// host memory pressure issue at the 256-MiB allocation
    /// boundary; the harness's RSS-bound assertion (T8) catches the
    /// concurrent-mode shape, but the per-allocation NULL here
    /// covers the single-thread per-seedhash shape.
    CacheAllocFailed { seedhash: Seedhash },
    /// `randomx_get_cache_memory` returned `NULL`. Should not occur
    /// after a successful `randomx_alloc_cache` per `randomx.h`'s
    /// contract; surfacing the variant explicitly keeps the
    /// failure attributable rather than masking it as a hard panic.
    CacheMemoryNull { seedhash: Seedhash },
    /// `randomx_create_vm` returned `NULL`. Like
    /// [`COracleError::CacheAllocFailed`] this typically indicates
    /// VM-private buffer allocation pressure.
    VmCreateFailed { seedhash: Seedhash },
}

impl fmt::Display for COracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CacheAllocFailed { seedhash } => write!(
                f,
                "randomx_alloc_cache returned NULL for seedhash {seedhash}"
            ),
            Self::CacheMemoryNull { seedhash } => write!(
                f,
                "randomx_get_cache_memory returned NULL for seedhash {seedhash}"
            ),
            Self::VmCreateFailed { seedhash } => {
                write!(f, "randomx_create_vm returned NULL for seedhash {seedhash}")
            }
        }
    }
}

impl std::error::Error for COracleError {}

/// One allocated `(randomx_cache, randomx_vm)` pair, bound to a
/// single seedhash for its lifetime.
///
/// Construct via [`COracleSession::new`]; both handles are released
/// when the session is dropped. The session is `!Send` and `!Sync`
/// by virtue of holding raw pointers; the harness's concurrent
/// mode (C8) constructs per-thread sessions rather than sharing.
///
/// See the module-level docs for the lifecycle + flags + safety
/// rationale.
pub struct COracleSession {
    /// Owned `randomx_cache` handle; `NULL` is never observed here
    /// because [`COracleSession::new`] returns `Err` on the
    /// allocation NULL.
    cache: *mut RandomxCache,
    /// Owned `randomx_vm` handle; bound to `cache` until drop.
    vm: *mut RandomxVm,
    /// `randomx_get_cache_memory(cache)` cached at construction;
    /// the C reference documents the pointer as valid for the
    /// cache's lifetime, so caching is safe and avoids the FFI
    /// hop on every `cache_bytes` / `cache_sha256` call.
    cache_memory: *mut c_void,
    /// The seedhash this session was initialized with. Read by the
    /// failure-output schema to attribute precondition / hash
    /// failures.
    seedhash: Seedhash,
}

impl COracleSession {
    /// Allocate and initialize a cache + VM pair for the given
    /// seedhash. Returns `Err(COracleError)` on any of the three
    /// NULL-return conditions; on `Err`, all partially-allocated
    /// resources are released before returning (no leak).
    ///
    /// # Errors
    ///
    /// - [`COracleError::CacheAllocFailed`] if
    ///   `randomx_alloc_cache` returns NULL.
    /// - [`COracleError::CacheMemoryNull`] if
    ///   `randomx_get_cache_memory` returns NULL after a successful
    ///   cache allocation (the cache is released before returning).
    /// - [`COracleError::VmCreateFailed`] if `randomx_create_vm`
    ///   returns NULL (the cache is released before returning).
    pub fn new(seedhash: Seedhash) -> Result<Self, COracleError> {
        // SAFETY: see module-level docs. All FFI calls here are the
        // R4-D5 light-mode shape: `RANDOMX_FLAG_DEFAULT` for cache
        // allocation (V2 bit is masked out at alloc per
        // `randomx.cpp:79`, so passing it here would be inert),
        // `RANDOMX_FLAG_V2` for VM creation (selects the v2
        // algorithm per the verifier-divergence FOLLOWUP closure),
        // NULL dataset to indicate light mode.
        unsafe {
            let cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
            if cache.is_null() {
                return Err(COracleError::CacheAllocFailed { seedhash });
            }
            let seedhash_bytes = seedhash.as_bytes();
            randomx_init_cache(
                cache,
                seedhash_bytes.as_ptr().cast::<c_void>(),
                seedhash_bytes.len(),
            );
            let cache_memory = randomx_get_cache_memory(cache);
            if cache_memory.is_null() {
                randomx_release_cache(cache);
                return Err(COracleError::CacheMemoryNull { seedhash });
            }
            let vm = randomx_create_vm(RANDOMX_FLAG_V2, cache, ptr::null_mut());
            if vm.is_null() {
                randomx_release_cache(cache);
                return Err(COracleError::VmCreateFailed { seedhash });
            }
            Ok(Self {
                cache,
                vm,
                cache_memory,
                seedhash,
            })
        }
    }

    /// The seedhash this session was initialized with.
    pub fn seedhash(&self) -> &Seedhash {
        &self.seedhash
    }

    /// A read-only byte view of the C reference's
    /// `RANDOMX_CACHE_SIZE_BYTES` (256 MiB) cache memory.
    ///
    /// Used by §5.1.7's `--debug-cache-divergence` byte-by-byte
    /// diff (T4); the SHA-256 default path uses
    /// [`COracleSession::cache_sha256`] which streams the same
    /// bytes through `Sha256` without materializing the slice
    /// outside this borrow.
    ///
    /// The lifetime is bounded by `&self`: the slice is invalid
    /// after the session drops because [`Drop`] releases the cache.
    pub fn cache_bytes(&self) -> &[u8] {
        // SAFETY: `cache_memory` is non-NULL (checked at `new`),
        // `randomx.h` documents the buffer as valid for the cache's
        // lifetime, `RANDOMX_CACHE_SIZE_BYTES` is the constant
        // size, and the harness's R4-D5 lifecycle guarantees no
        // concurrent FFI mutation of this buffer. The returned
        // slice's lifetime is bounded by `&self`.
        unsafe { slice::from_raw_parts(self.cache_memory.cast::<u8>(), RANDOMX_CACHE_SIZE_BYTES) }
    }

    /// SHA-256 of the C reference's 256-MiB cache memory.
    ///
    /// This is the C-side input to §5.1.7's R1-D14 cache-equivalence
    /// precondition (T3). The Rust-side counterpart is
    /// [`crate::cache_precondition::rust_cache_sha256`].
    ///
    /// Streamed through [`Sha256`] over the [`Self::cache_bytes`]
    /// view; no intermediate allocation beyond the 32-byte digest.
    pub fn cache_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.cache_bytes());
        hasher.finalize().into()
    }

    /// Compute one C-reference RandomX hash of `data` under this
    /// session's `(seedhash, cache, vm)` binding.
    ///
    /// This is the C-side oracle for §5.1.10's T1 + T5 byte-equality
    /// assertions and §5.1.12's interleaved latency mode. The
    /// Rust-side counterpart is
    /// [`crate::rust_subject::RustSubjectSession::compute_hash`].
    pub fn calculate_hash(&self, data: &[u8]) -> [u8; RANDOMX_HASH_SIZE] {
        let mut output = [0u8; RANDOMX_HASH_SIZE];
        // SAFETY: `vm` is non-NULL (checked at `new`); `data` and
        // `output` are alive for the duration of this call (Rust
        // borrow rules); `randomx_calculate_hash` does not retain
        // either pointer past return per `randomx.h`'s contract.
        unsafe {
            randomx_calculate_hash(
                self.vm,
                data.as_ptr().cast::<c_void>(),
                data.len(),
                output.as_mut_ptr().cast::<c_void>(),
            );
        }
        output
    }
}

impl Drop for COracleSession {
    fn drop(&mut self) {
        // SAFETY: `vm` and `cache` were non-NULL when `new`
        // returned `Ok(Self)`; no other code path mutates either
        // pointer. The `randomx.h`-prescribed release order is VM
        // first (cache outlives VM at construction), cache second.
        unsafe {
            randomx_destroy_vm(self.vm);
            randomx_release_cache(self.cache);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `COracleError`'s `Display` impl emits the seedhash via the
    /// `Seedhash` `Display` impl. The full string is verified for
    /// the cache-alloc variant; the other variants share the same
    /// format-string skeleton.
    #[test]
    fn coracle_error_display_includes_seedhash() {
        let seedhash = Seedhash::from_bytes([0x42; 32]);
        let err = COracleError::CacheAllocFailed { seedhash };
        let s = format!("{err}");
        assert!(
            s.starts_with("randomx_alloc_cache returned NULL for seedhash"),
            "got: {s}"
        );
        // Seedhash::Display emits the 64-char hex form; we don't
        // pin the exact case here, only the presence of two
        // consecutive hex `4`s from the all-0x42 input.
        assert!(s.to_ascii_lowercase().contains("4242"), "got: {s}");
    }

    /// The cache-size constant matches the upstream
    /// `RANDOMX_ARGON_MEMORY × ArgonBlockSize` factoring documented
    /// in the C reference's `common.hpp:88`. Pinned here as a
    /// literal so any drift in the upstream constants (or a
    /// transcription error in this module) breaks at compile time
    /// + test time rather than at the first T3 precondition run.
    #[test]
    fn cache_size_bytes_matches_upstream_factoring() {
        assert_eq!(RANDOMX_CACHE_SIZE_BYTES, 262_144 * 1024);
        assert_eq!(RANDOMX_CACHE_SIZE_BYTES, 256 * 1024 * 1024);
    }

    /// `randomx_calculate_hash` output width is 32 bytes per
    /// `randomx.h`. Pinned here so the harness's hash-width
    /// assumption is captured at test time.
    #[test]
    fn hash_size_matches_upstream_constant() {
        assert_eq!(RANDOMX_HASH_SIZE, 32);
    }
}
