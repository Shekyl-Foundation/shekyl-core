// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Phase 2F cfg-gated `VmStatePool` for `compute_hash` per-call
//! allocation amortization.
//!
//! # Substrate
//!
//! Per [`docs/design/RANDOMX_V2_PHASE2F_PLAN.md`](../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md)
//! §3.3 Round 3, the pool body is implemented behind
//! `#[cfg(any(test, feature = "internal-pool-bench"))]` regardless
//! of the §3.4 R1-D4 outcome. The cfg-gated form lets the
//! [`benches/compute_hash_alloc.rs`](../benches/compute_hash_alloc.rs)
//! bench harness measure the pool path's actual A/B savings against
//! the no-pool path; the bench result determines whether the
//! cfg-gate is removed (pool promoted to production per §3.4 Branch
//! C) or retained (pool stays as bench-only per Branch A).
//!
//! Round 1's circular-sequencing problem ("can't bench the pool
//! without implementing the pool, can't justify the pool without
//! benching it") is closed by making the pool always-implemented
//! behind a feature gate that is never enabled in production.
//!
//! # Pool semantics
//!
//! [`VmStatePool`] holds up to `capacity` recycled
//! [`crate::vm::VmState`] instances in an internal `Mutex<Vec<...>>`.
//! [`VmStatePool::acquire`] returns a guard that lends a
//! [`crate::vm::VmState`] (popping from the pool, or constructing a
//! fresh one via [`crate::vm::VmState::new`] if the pool is empty);
//! the guard's [`Drop`] returns the instance to the pool if there is
//! capacity, or drops it otherwise. The pool is plain LIFO with no
//! aging.
//!
//! Capacity is enforced at *release* time, not at *acquire* time:
//! `acquire` always succeeds (constructing a fresh `VmState` when the
//! pool is empty), but a guard's drop only puts the instance back if
//! `inner.len() < capacity`. This matches the bench's intended use
//! where the binding fanout is the *expected steady-state*
//! concurrency level and the pool size caps the upper bound on
//! retained allocations.
//!
//! # `compute_hash_with_pool`
//!
//! [`compute_hash_with_pool`] is the bench entry point that the
//! `--features internal-pool-bench` build of
//! `benches/compute_hash_alloc.rs` calls via
//! `compute_hash_with_pool(&pool, &prepared, data)`. Its body
//! acquires a [`crate::vm::VmState`] from the pool and feeds it
//! through [`crate::vm::compute_hash_inner`] — the same dispatch
//! body that the production no-pool [`crate::compute_hash`] uses.
//! The dispatch body is the single source of truth; the pool path
//! and the no-pool path differ only in where the [`crate::vm::VmState`]
//! comes from.
//!
//! # Visibility discipline
//!
//! Per Phase 2c Decision #7 (no public `VmPool` type), the
//! pool's API surface is kept off the production rustdoc and out
//! of the no-feature build. The mechanism is two-layered:
//!
//! 1. The whole module is gated by
//!    `#[cfg(any(test, feature = "internal-pool-bench"))]`, so the
//!    no-feature production build never compiles the pool body.
//! 2. Within the gated module, [`VmStatePool`] and
//!    [`compute_hash_with_pool`] are marked `#[doc(hidden)] pub`,
//!    not `pub(crate)`: the criterion bench in
//!    [`benches/compute_hash_alloc.rs`](../benches/compute_hash_alloc.rs)
//!    is a separate cargo target (an external compilation unit),
//!    so it can only name items that are `pub` at the crate
//!    boundary. `pub(crate)` would forbid the bench from naming
//!    `VmStatePool::new` or `compute_hash_with_pool` at all.
//!    `#[doc(hidden)]` keeps the `pub` symbols off the published
//!    rustdoc API surface.
//!
//! [`VmStateGuard`] *is* `pub(crate)` because its
//! `Deref::Target = VmState` references the `pub(crate)`
//! [`crate::vm::VmState`] type and Rust forbids `pub` types from
//! exposing crate-private types in their public interface (E0446).
//! The bench harness never names the guard directly; it goes
//! through [`compute_hash_with_pool`], which acquires/releases the
//! guard internally.
//!
//! Phase 3a's promotion-to-production (§3.4 Round 3 Branch C,
//! §8 commit 5) flips the cfg-gate to unconditional and
//! simultaneously narrows [`VmStatePool`] from
//! `#[doc(hidden)] pub` down to `pub(crate)`: the FFI shim layer
//! lives inside the crate, so post-promotion the type does not
//! need to cross the crate boundary at all, and the bench-only
//! `pub` carve-out is rescinded. The Branch A measurement landed
//! in this PR did not trigger that promotion; the type's current
//! `#[doc(hidden)] pub` shape is the bench-only state.

#![cfg(any(test, feature = "internal-pool-bench"))]

use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

use crate::vm::VmState;

/// Recycled-allocation pool for [`VmState`] instances.
///
/// See module-level rustdoc for the substrate, semantics, and
/// visibility discipline.
///
/// `#[doc(hidden)] pub` (rather than `pub(crate)`) because the
/// criterion bench in
/// [`benches/compute_hash_alloc.rs`](../benches/compute_hash_alloc.rs)
/// is a separate cargo target and can only name items that are
/// `pub` at the crate boundary. `#[doc(hidden)]` keeps the symbol
/// off the published rustdoc, and the surrounding
/// `#[cfg(any(test, feature = "internal-pool-bench"))]` keeps it
/// out of the no-feature production build entirely. Per Phase 2c
/// Decision #7 this is *not* a public-API promise — the type is
/// reachable only when a consumer opts into the bench feature
/// flag. Promotion to production (per §3.4 Round 3 Branch C)
/// narrows the visibility to `pub(crate)` simultaneously with the
/// cfg-gate removal; the Branch A measurement landed in this PR
/// did not trigger that promotion.
#[doc(hidden)]
pub struct VmStatePool {
    /// LIFO pool of recycled `VmState` instances. Capped at
    /// [`Self::capacity`] entries; surplus instances are dropped on
    /// release rather than retained.
    ///
    /// `Mutex` rather than `parking_lot::Mutex` per `17-dependency-discipline.mdc`:
    /// no new workspace dep is added by Phase 2F. Lock-hold time is
    /// bounded by `Vec::pop` / `Vec::push` (a handful of pointer
    /// operations); contention is bounded by the pool's capacity
    /// (typically `binding_fanout + 1` per §3.5 R1-D5 Round 3).
    inner: Mutex<Vec<VmState>>,
    /// Maximum number of recycled instances retained between calls.
    /// Capacity is determined by the caller per §3.5 R1-D5
    /// Round 3 (runtime parameter, not a compile-time constant); the
    /// methodology is `binding_fanout + 1` where binding fanout is
    /// `min(threadpool_max, m_max_prepare_blocks_threads)` at the
    /// daemon's runtime state.
    ///
    /// Read-only after construction (no `Mutex` wrapper); the
    /// release path reads `capacity` while holding `inner`'s mutex
    /// to compare against `inner.len()`.
    capacity: usize,
}

impl VmStatePool {
    /// Construct a [`VmStatePool`] with the given retention
    /// `capacity` (no instances pre-allocated).
    ///
    /// Per `RANDOMX_V2_PHASE2F_PLAN.md` §3.5 Round 3, `capacity`
    /// should be `binding_fanout + 1` derived at the call site
    /// (Phase 3a's FFI shim) from
    /// `min(tools::threadpool::getInstanceForCompute().get_max_concurrency(),
    /// m_max_prepare_blocks_threads)`. The verifier crate does not
    /// derive the number itself; the methodology is design-time-fixed,
    /// the value is per-deployment.
    ///
    /// `capacity = 0` is permitted: every release drops the
    /// [`VmState`] (no retention). This degenerate case is useful
    /// for negative-control benchmarking — the pool exists, but its
    /// observable behavior is identical to the no-pool path. The
    /// bench harness does not currently exercise this case.
    #[doc(hidden)]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }

    /// Acquire a [`VmState`] from the pool, lending it through a
    /// [`VmStateGuard`] that returns it on drop.
    ///
    /// If the pool is empty, [`VmState::new`] allocates a fresh
    /// instance (the same allocation cost the no-pool path pays per
    /// call). Subsequent acquires after the guard's drop hit the
    /// pool's recycled entry instead, amortizing the allocation cost
    /// across calls.
    ///
    /// The guard pins the pool by reference, so the pool must
    /// outlive the guard (lifetime `'p`). Concurrent acquires from
    /// different threads each pop their own entry under the mutex;
    /// the pool serializes acquire/release strictly, but the
    /// dispatch loop's hot path runs entirely outside the lock
    /// (inside [`compute_hash_inner`]).
    ///
    /// `pub(crate)` rather than `pub` because [`VmStateGuard`]'s
    /// `Deref::Target = VmState` would leak the `pub(crate)`
    /// `VmState` through a `pub` interface (E0446). The bench
    /// harness reaches the pool exclusively through
    /// [`compute_hash_with_pool`], which calls `acquire` from
    /// within this crate; external callers do not need direct
    /// guard access.
    ///
    /// [`compute_hash_inner`]: crate::vm::compute_hash_inner
    pub(crate) fn acquire(&self) -> VmStateGuard<'_> {
        let popped = {
            let mut inner = self
                .inner
                .lock()
                .expect("VmStatePool::acquire — inner mutex poisoned");
            inner.pop()
        };
        let vm = popped.unwrap_or_else(VmState::new);
        VmStateGuard {
            pool: self,
            vm: Some(vm),
        }
    }
}

impl Default for VmStatePool {
    /// Per `RANDOMX_V2_PHASE2F_PLAN.md` §3.5 Round 3, the
    /// `Default::default()` implementation is **only safe in
    /// `#[cfg(test)]`** — the test build uses a fixed default
    /// capacity of 4 (matching the typical
    /// `m_max_prepare_blocks_threads` cap per §3.5 R1-D5 Round 1) so
    /// in-crate tests can construct a pool without naming a
    /// capacity. Outside `#[cfg(test)]`, calling `Default::default()`
    /// **panics** to enforce the discipline that Phase 3a's FFI
    /// shim must explicitly pass an R1-D5-derived capacity.
    ///
    /// This shape is the named substitute for the Round 1
    /// `pub(crate) const POOL_CAPACITY` compile-time constant: the
    /// methodology is design-time-fixed (binding fanout + 1), the
    /// number is per-deployment, and a panic-on-default keeps the
    /// "explicit capacity required" discipline auditable rather than
    /// silently accepting a stale impl-PR-baked value.
    fn default() -> Self {
        #[cfg(test)]
        {
            VmStatePool::new(4)
        }
        #[cfg(all(not(test), feature = "internal-pool-bench"))]
        {
            panic!(
                "VmStatePool::default() is not safe outside tests; \
                 Phase 3a's FFI shim must pass an explicit capacity \
                 derived per RANDOMX_V2_PHASE2F_PLAN.md §3.5 R1-D5 \
                 methodology (`binding_fanout + 1` where binding \
                 fanout is `min(threadpool_max, \
                 m_max_prepare_blocks_threads)`)."
            )
        }
    }
}

/// RAII guard returning a [`VmState`] to its [`VmStatePool`] on
/// [`Drop`].
///
/// The guard implements [`Deref`] / [`DerefMut`] to [`VmState`] so
/// the dispatch loop body can use it transparently. The
/// [`compute_hash_with_pool`] entry-point shim does exactly that.
///
/// `pub(crate)` (not `#[doc(hidden)] pub`) because the guard's
/// associated `Deref::Target = VmState` references the
/// `pub(crate)` [`VmState`] type, and Rust forbids `pub` interfaces
/// from leaking crate-private types (E0446). The guard is reached
/// only through [`VmStatePool::acquire`] from within this crate;
/// the bench harness's external surface is
/// [`compute_hash_with_pool`].
pub(crate) struct VmStateGuard<'p> {
    pool: &'p VmStatePool,
    /// `Option` because [`Drop`] needs to take ownership of the
    /// `VmState` to push it back into the pool. `vm.is_none()` only
    /// during the guard's drop tear-down; at any time the user can
    /// call [`Deref`] / [`DerefMut`], the field is `Some(_)`.
    vm: Option<VmState>,
}

impl<'p> Deref for VmStateGuard<'p> {
    type Target = VmState;
    fn deref(&self) -> &Self::Target {
        self.vm
            .as_ref()
            .expect("VmStateGuard::deref — vm taken before drop")
    }
}

impl<'p> DerefMut for VmStateGuard<'p> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vm
            .as_mut()
            .expect("VmStateGuard::deref_mut — vm taken before drop")
    }
}

impl<'p> Drop for VmStateGuard<'p> {
    fn drop(&mut self) {
        let Some(vm) = self.vm.take() else {
            // Already drained (paranoia path: a panic between `take()`
            // calls would leave `vm` in `None`; nothing to release).
            return;
        };
        // Mutex-poisoning policy diverges between `acquire` and
        // `Drop` deliberately:
        //
        //   - [`VmStatePool::acquire`] runs in normal control flow
        //     and propagates poison via `expect(...)`. A panic at
        //     acquire is recoverable and surfaces the broken
        //     invariant to the bench harness loudly.
        //   - This [`Drop`] may run during an in-progress unwind
        //     (the bench iteration body panicked, the guard's
        //     stack-frame is being torn down). A second panic
        //     during unwind triggers `abort()` (Rust's
        //     double-panic policy), which is louder than the
        //     primary failure and obscures the diagnostic chain.
        //
        // The poison is therefore swallowed via
        // `Err(poison) => poison.into_inner()`: whichever shape
        // the inner `Vec` is in, we either rejoin the pool (if
        // capacity allows) or drop the `VmState` here, without
        // escalating an already-broken state to abort. Lock-hold
        // time is bounded by `Vec::push` (a few pointer ops) so
        // the swallow window is sub-microsecond. `try_lock` is
        // not used because `Drop` runs at the end of every
        // `compute_hash_with_pool` call: the lock is virtually
        // always uncontended; spinning on `try_lock` would
        // complicate the contract without measurable benefit.
        let mut inner = match self.pool.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        if inner.len() < self.pool.capacity {
            inner.push(vm);
        }
        // else: drop `vm` (deallocates scratchpad + program).
    }
}

/// Bench-only entry-point shim: acquire a [`VmState`] from `pool`,
/// run [`crate::vm::compute_hash_inner`], release on guard drop.
///
/// Per `RANDOMX_V2_PHASE2F_PLAN.md` §3.3 Round 3, this is the
/// `B-pool-on::per_call` bench's call target. The
/// `compute_hash_alloc::with_pool::per_call` criterion bench in
/// `benches/compute_hash_alloc.rs` calls this function repeatedly
/// against a pre-derived [`crate::PreparedCache`]; the pool persists
/// across iterations so the second-and-subsequent calls hit the
/// pool's recycled entry, exposing the A/B delta against the no-pool
/// path's per-call [`VmState::new`] cost.
///
/// `#[doc(hidden)] pub` so the bench harness (an external cargo
/// target) can name the function. Production builds never compile
/// this entry point: the cfg-gate
/// `#[cfg(any(test, feature = "internal-pool-bench"))]` excludes it
/// from the no-feature build that ships in releases.
#[doc(hidden)]
pub fn compute_hash_with_pool(
    pool: &VmStatePool,
    prepared: &crate::PreparedCache,
    data: &[u8],
) -> [u8; 32] {
    let mut guard = pool.acquire();
    crate::vm::compute_hash_inner(&mut guard, prepared, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreparedCache, Seedhash};

    /// Canonical test seedhash for pool-equivalence checks. Distinct
    /// from cache-store / vm test seedhashes to keep failure modes
    /// scoped.
    const POOL_TEST_SEEDHASH: [u8; 32] = *b"shekyl-randomx-v2-pool-test-seed";

    /// 32-byte canonical test data. Equally arbitrary; only the
    /// determinism of the output across pool / no-pool paths matters
    /// for these tests.
    const POOL_TEST_DATA: &[u8] = b"shekyl-randomx-v2-pool-test-data-padding-bytes";

    /// T-PL-1: `acquire` on an empty pool produces a usable `VmState`
    /// (functional sanity check that the pool's empty-path doesn't
    /// regress to e.g., panicking on `Vec::pop`).
    #[test]
    fn t_pl_1_acquire_from_empty_pool_returns_fresh_vm_state() {
        let pool = VmStatePool::new(4);
        let guard = pool.acquire();
        // Smoke check: scratchpad is allocated to the right size.
        assert_eq!(
            guard.scratchpad.len(),
            crate::vm::RANDOMX_SCRATCHPAD_L3,
            "fresh VmState's scratchpad length must equal RANDOMX_SCRATCHPAD_L3"
        );
        drop(guard);
    }

    /// T-PL-2: drop returns the `VmState` to the pool when capacity
    /// allows. Verified by checking that the pool's internal `Vec`
    /// length increases from 0 to 1 after a single
    /// acquire-then-drop cycle.
    #[test]
    fn t_pl_2_drop_releases_to_pool_under_capacity() {
        let pool = VmStatePool::new(4);
        {
            let _guard = pool.acquire();
        }
        let inner = pool.inner.lock().unwrap();
        assert_eq!(
            inner.len(),
            1,
            "after one acquire-then-drop with capacity = 4, \
             pool should retain exactly 1 instance",
        );
    }

    /// T-PL-3: drop discards the `VmState` when the pool is at
    /// capacity. Capacity = 0 forces every release to be a discard.
    #[test]
    fn t_pl_3_drop_discards_when_at_capacity() {
        let pool = VmStatePool::new(0);
        {
            let _guard = pool.acquire();
        }
        let inner = pool.inner.lock().unwrap();
        assert_eq!(
            inner.len(),
            0,
            "capacity = 0 must cause every release to discard",
        );
    }

    /// T-PL-4: `compute_hash_with_pool` produces the same output as
    /// the production [`crate::compute_hash`] for the same
    /// `(prepared, data)` input. This is the load-bearing
    /// equivalence check: if the pool path and the no-pool path
    /// diverge, the cfg-gate's bench-only artifact would not be a
    /// valid measurement target for the production-path A/B
    /// disposition.
    ///
    /// Uses `Cache::derive` (one fresh derivation), so this test
    /// pays the full cache-derive cost (~340 ms on the reference
    /// machine). Run cost is bounded by criterion's measurement
    /// path, not the test harness; this single derivation is the
    /// minimum needed to construct a `PreparedCache`.
    #[test]
    fn t_pl_4_pool_path_matches_no_pool_path_byte_for_byte() {
        let prepared = PreparedCache::derive(Seedhash::from_bytes(POOL_TEST_SEEDHASH));
        let no_pool = crate::compute_hash(&prepared, POOL_TEST_DATA);

        let pool = VmStatePool::new(4);
        let with_pool = compute_hash_with_pool(&pool, &prepared, POOL_TEST_DATA);

        assert_eq!(
            no_pool, with_pool,
            "pool path output must match no-pool path output \
             byte-for-byte; divergence indicates pool-reuse residue \
             leaking into the dispatch (per RANDOMX_V2_PHASE2F_PLAN.md \
             §3.3 Round 3 pool-reuse-safety analysis)",
        );
    }

    /// T-PL-5: two consecutive `compute_hash_with_pool` calls
    /// against the same pool produce identical output for identical
    /// input. This catches pool-reuse residue: the second call's
    /// `VmState` is the recycled instance from the first call's
    /// drop, so any field-carry-over that the dispatch loop reads
    /// before writing would surface here as a divergence between
    /// call #1 and call #2.
    #[test]
    fn t_pl_5_consecutive_pool_calls_produce_identical_output() {
        let prepared = PreparedCache::derive(Seedhash::from_bytes(POOL_TEST_SEEDHASH));
        let pool = VmStatePool::new(4);

        let first = compute_hash_with_pool(&pool, &prepared, POOL_TEST_DATA);
        let second = compute_hash_with_pool(&pool, &prepared, POOL_TEST_DATA);

        assert_eq!(
            first, second,
            "second pool call (recycled VmState) must produce \
             identical output to the first call (fresh VmState); \
             divergence indicates a field carries over and is read \
             before being written by the dispatch pipeline",
        );
    }

    /// T-PL-6: `Default::default()` constructs a `VmStatePool` with
    /// the test-default capacity (4) under `#[cfg(test)]`. The
    /// non-test panic path is exercised by the
    /// `internal-pool-bench`-only doc-test or, more practically, by
    /// downstream benches running under the feature flag (the panic
    /// is the discipline; testing the panic message is overkill).
    #[test]
    fn t_pl_6_default_constructs_with_test_default_capacity() {
        let pool = VmStatePool::default();
        assert_eq!(pool.capacity, 4, "test-default capacity is 4");
    }

    /// T-PL-7: pool retention bounded by capacity — three
    /// concurrent leases into a capacity-2 pool retain exactly 2
    /// instances (the third release discards).
    ///
    /// Holds three concurrent leases (three fresh allocations
    /// because the pool starts empty) and then lets all three
    /// guards drop together. Drop order is reverse-declaration
    /// order in Rust: `g3` drops first into an empty pool
    /// (`0 < 2` → push, len = 1), then `g2` (`1 < 2` → push,
    /// len = 2), then `g1` (`2 < 2` is false → discard). Final
    /// pool length is 2.
    ///
    /// Sequential acquire-then-drop (the prior shape of this
    /// test) would only ever leave 1 instance in the pool — each
    /// iteration pops the sole entry first, so the pool oscillates
    /// 0 → 1 → 0 → 1 → … and never reaches `len = capacity`.
    /// Concurrent leases force allocation under the
    /// `inner.pop().unwrap_or_else(VmState::new)` path and surface
    /// the `inner.len() < self.pool.capacity` cap on release.
    #[test]
    fn t_pl_7_capacity_caps_retained_instances() {
        let pool = VmStatePool::new(2);
        {
            let _g1 = pool.acquire();
            let _g2 = pool.acquire();
            let _g3 = pool.acquire();
        }
        let inner = pool.inner.lock().unwrap();
        assert_eq!(
            inner.len(),
            2,
            "capacity = 2 must cap retained instances at 2 \
             regardless of concurrent-lease count",
        );
    }
}
