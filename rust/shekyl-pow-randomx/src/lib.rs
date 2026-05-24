// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pure-software RandomX v2 verifier for Shekyl daemon block validation.
//!
//! Consumed exclusively by `shekyl-ffi` (Phase 3, not in scope at this
//! commit); never linked into the C++ miner path. The Monero RandomX
//! C/C++ library at `external/randomx-v2/` (pinned at fork commit
//! `aaafe71`, v2.0.1) remains the miner; this crate is the verifier
//! and the verifier only. See
//! [`RANDOMX_V2_PLAN.md`](../../docs/design/RANDOMX_V2_PLAN.md)'s
//! "Permanent architectural decisions" §1.
//!
//! # Decision substrate (locked; do not relitigate)
//!
//! - **Spec-first.**
//!   [`specs.md`](../../external/randomx-v2/doc/specs.md) is the source
//!   of truth. Disagreements with the C reference at
//!   `external/randomx-v2/src/` are bugs filed against the C fork,
//!   not amendments to this port. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §3.
//! - **Derived-first.** `PreparedCache`, `Vm`, and `Hash` are
//!   transform-shaped per
//!   [`18-type-placement.mdc`](../../.cursor/rules/18-type-placement.mdc):
//!   their canonical definitions are functions (e.g.
//!   `PreparedCache::derive(seedhash) -> PreparedCache`); storage
//!   is a memoization of the function's output. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §4.
//! - **Isolation invariants.** No `#[no_mangle]`, no `extern "C" fn`,
//!   no `#[export_name]` (bare or `#[unsafe(…)]`), no module-level
//!   runtime-mutable state (`Mutex`, `RwLock`, `OnceCell`, `OnceLock`,
//!   `Lazy`, `static mut`, module-scope atomics). Immutable `const`
//!   tables are allowed. Phase 2f ships the CI greps that enforce
//!   these mechanically; the crate is written from its first commit as
//!   if those greps were already live. See
//!   [`RANDOMX_V2_RUST.md`](../../docs/design/RANDOMX_V2_RUST.md) §7.2.
//!
//! # Scope at this PR (Phase 2c)
//!
//! Phase 2a landed the workspace scaffold and the Argon2d "memory fill"
//! primitive. Phase 2b landed the AES round primitives, `AesGenerator1R`
//! / `AesGenerator4R` / `AesHash1R` composites, `Blake2Generator`, and
//! `SuperscalarHash` program generator + executor. Phase 2c lands the
//! cache + VM substrate end-to-end, with per-stage and end-to-end
//! spec-vector parity against the v2 fork at pin `aaafe71` (per the
//! `cache_derive_fingerprint` T1 vector and the seven `vm/*` T3-T8
//! vectors under `tests/vectors/reference/`):
//!
//! - `src/seedhash.rs` — `pub Seedhash` newtype wrapping the
//!   32-byte seedhash. Per Phase 2F §1.1 Round 2, the type is
//!   the typed key consumed by [`PreparedCache::derive`] and
//!   indexed by the (Phase 2F) `CacheStore`'s slot map; the
//!   newtype distinguishes seedhash bytes from arbitrary 32-byte
//!   buffers (output hashes, candidate digests) at every call
//!   site.
//! - `src/prepared_cache.rs` — `pub PreparedCache` + `pub fn
//!   PreparedCache::derive(Seedhash) -> PreparedCache`. The
//!   bundle pairs the derived cache with the seedhash it was
//!   derived from; per Phase 2F §1.1 / §3.1 Round 2 it is the
//!   public construction path for cache-bearing values, replacing
//!   Phase 2c's `(&Cache, &Seedhash)` parameter pair on
//!   [`compute_hash`] with a single bundled argument that the type
//!   system enforces consistent.
//! - `src/cache.rs` — `pub(crate) Cache` + `pub(crate) fn
//!   Cache::derive(&Seedhash) -> Cache` (the 256 MiB Argon2d fill
//!   plus eight `Blake2Generator`-seeded `generateSuperscalar`
//!   programs from Phase 2a + Phase 2b primitives),
//!   `pub(crate) Cache::derive_item`, and
//!   `pub(crate) Cache::item_bytes` for the per-iteration
//!   dataset-item read path. The narrowing to `pub(crate)`
//!   landed at Phase 2F §1.1 Round 2; FFI consumers go through
//!   [`PreparedCache::derive`] / [`compute_hash`].
//! - `src/vm.rs` — `pub fn compute_hash(&PreparedCache, &[u8])`,
//!   `pub(crate) VmState` (2 MiB scratchpad, register file, per-
//!   program init from entropy), and `dispatch_instruction(...)`.
//!   Phase 2c landed the dispatch as a NOP body per §5.1.1 of the
//!   plan doc; Phase 2d replaced it in-place with the real table-
//!   driven per-opcode dispatch per
//!   [`RANDOMX_V2_PHASE2D_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2D_PLAN.md)
//!   §3, which is what currently ships. References to "stub-NOP"
//!   below describe the Phase-2c-era T3-T8 vectors as they were
//!   originally generated; the end-to-end real-dispatch parity
//!   vector is T16 per Phase 2d.
//! - `src/cache_store.rs` — `pub CacheStore` capacity-2
//!   sticky-canonical store landed by Phase 2F §3.1 Round 2.
//!   Two slots ([`PreparedCache`]-typed canonical + transient)
//!   plus an in-flight derivation map close the F1 (cache-
//!   derivation DoS amplification) and F3 (thundering-herd) attack
//!   classes; cleanup-on-publish closes F4 (unbounded in-flight
//!   map growth). Internal synchronization uses per-slot
//!   `RwLock<Option<Arc<PreparedCache>>>` plus
//!   `Mutex<HashMap<Seedhash, Arc<DerivationSlot>>>` (no new
//!   workspace dependency added).
//! - `tests/vectors/reference/cache/` + `tests/vectors/reference/vm/`
//!   — 8 Phase-2c reference vectors (T1: cache fingerprint; T2:
//!   dataset item batch; T3-T8: VM scratchpad init, register init,
//!   program parse, sp_addr derivation, AES-mix snapshot, T8 the
//!   then-current end-to-end stub-NOP hash) pre-computed by the
//!   reviewer-runnable C++ generator at
//!   `tests/vectors/reference/_generator/phase2c/`. Phase 2d added
//!   T16 for end-to-end real-dispatch parity against the C
//!   reference, which is what currently gates per-PR consensus
//!   parity; T8 remains as the dispatch-substitution check that
//!   the substrate around `dispatch_instruction` is unchanged.
//! - `benches/cache_derive.rs` + `benches/compute_hash_alloc.rs` —
//!   criterion baselines. `Cache::derive` was scoped at ≤ 200 ms
//!   median per §5.8; the §8 ≤ 100 µs budget applied to the
//!   `compute_hash` *allocation skeleton* specifically (an
//!   allocation-only sub-bench has not landed yet), and the
//!   `compute_hash_alloc` bench measures the full pipeline as an
//!   informational baseline rather than a PR gate. The Phase 2c
//!   baseline was taken under stub-NOP dispatch; Phase 2d's real-
//!   dispatch baseline is recorded alongside it in
//!   `BENCH_RESULTS.md`. The reconciliation between the §8
//!   allocation-only budget and the empirical full-pipeline numbers
//!   is tracked as R0-D12 in `RANDOMX_V2_PHASE2C_PLAN.md` §14.
//!   Phase 2F §6.3 added the A/B `with_no_pool` / `with_pool`
//!   harness to the same file (the latter cfg-gated behind
//!   `--features internal-pool-bench`).
//! - `tests/perf/per_hash_latency.rs` — Phase 2g placeholder
//!   (`#[ignore]` + `unimplemented!()`) at the canonical 2g
//!   deliverable path per §5.8 R3-minor-2; 2g replaces the body
//!   in-place.
//!
//! Sub-PR ladder (per
//! [`RANDOMX_V2_PLAN.md`](../../docs/design/RANDOMX_V2_PLAN.md)
//! §"Track A — Phase 2"):
//!
//! - **2d (landed):** Per-opcode bytecode dispatch. In-place
//!   function-body replacement of `dispatch_instruction` inside
//!   `vm.rs` (no trait wiring, no impl swap, no signature change to
//!   `compute_hash`). T16 reference vector locks end-to-end parity
//!   against the C fork at pin `aaafe71`.
//! - **2f (landed):** `CacheStore` (the capacity-2 sticky-canonical
//!   store + in-flight derivation map described above), the cfg-
//!   gated `VmStatePool` (`#[doc(hidden)] pub` under `test` /
//!   `internal-pool-bench`), and `scripts/ci/check_randomx_crate_invariants.sh`
//!   — the §7.2 isolation invariants now have mechanical CI grep
//!   gates instead of "discipline-only" enforcement.
//! - **2g (planned):** C-side differential harness as a *separate*
//!   test-only artifact (not a `[dev-dependencies]` of this crate);
//!   the crate's own `cargo test` succeeds without the C library
//!   present. 2g also populates the
//!   `tests/perf/per_hash_latency.rs` placeholder landed by Phase
//!   2c.
//!
//! Phase 3 then exposes the verifier through `shekyl-ffi` and rewires
//! the C++ daemon to it; Phase 4 deletes the C++ verifier path.
//!
//! # Scope: public-input verification only
//!
//! This crate is designed for **public-input verification** (block
//! Proof-of-Work hashing). Secret-input use — e.g. hashing private
//! material with a RandomX-shaped construction (a wallet KDF, a
//! Proof-of-Work-shaped commitment scheme over private inputs, etc.)
//! — would require a separate threat model addressing allocator-
//! pressure side channels, scratchpad cache-line residency, and per-
//! iteration timing variance. No current or planned consumer uses
//! this crate with secret material. See
//! [`RANDOMX_V2_PHASE2C_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2C_PLAN.md)
//! §5.11.4 for the reopening criterion under
//! [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).

#![deny(unsafe_code)]
#![deny(missing_docs)]

mod aes;
mod argon2d;
mod blake2_generator;
mod cache;
mod cache_store;
pub(crate) mod fpu_rounding;
mod prepared_cache;
mod seedhash;
pub(crate) mod superscalar;
mod vm;

// Phase 2F §3.3 Round 3 cfg-gated `VmStatePool` body. The module is
// only compiled when the test harness is active or the
// `internal-pool-bench` feature is enabled (the bench harness's
// gate); production builds never see the pool body. See the module's
// rustdoc for the full visibility / promotion discipline.
#[cfg(any(test, feature = "internal-pool-bench"))]
mod vm_pool;

pub(crate) use cache::Cache;
pub use cache_store::CacheStore;
pub use prepared_cache::PreparedCache;
pub use seedhash::Seedhash;
pub use vm::compute_hash;

// Bench-only re-exports per Phase 2F §3.3 Round 3. `#[doc(hidden)]`
// keeps the surface out of the published rustdoc so the production
// API surface (the items above) is unchanged regardless of feature
// state. Production builds (no feature flag) never compile these
// bindings.
#[cfg(any(test, feature = "internal-pool-bench"))]
#[doc(hidden)]
pub use vm_pool::{compute_hash_with_pool, VmStatePool};
