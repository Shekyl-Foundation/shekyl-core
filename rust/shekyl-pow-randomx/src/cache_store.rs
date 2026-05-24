// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Capacity-2 sticky-canonical [`CacheStore`].
//!
//! Two-slot store: at-most-one canonical (sticky against eviction)
//! plus at-most-one transient (displaced by every new
//! [`CacheStore::lookup_or_derive`] when no slot match exists).
//! Concurrency-safe by interior mutability; per-slot
//! [`std::sync::RwLock`] separates lookup-heavy reads from rare
//! writes, and an internal in-flight-derivation map deduplicates
//! concurrent novel-seedhash lookups so only one Argon2d-512 fill
//! runs per seedhash regardless of contender count.
//!
//! # Why two slots and not "no CacheStore at all"
//!
//! A "no-CacheStore" alternative — let consumers manage
//! `Arc<PreparedCache>` directly, possibly with a per-consumer
//! in-flight-derivation map for thundering-herd protection — was
//! considered (Phase 2F §3.1 Round 2 Axes 2/3 alternatives (d) and
//! (g)) and rejected for **Arc-holding memory exhaustion**.
//! Without a CacheStore-layer cap, an attacker who induces
//! concurrent novel-seedhash lookups across multiple consumers (or
//! repeated within one consumer) gets the daemon to hold many
//! `Arc<PreparedCache>` clones whose total memory footprint scales
//! with the number of distinct seedhashes seen in the attack
//! window (each [`crate::PreparedCache`] is ~256 MiB). Capacity-2
//! at the CacheStore layer bounds this; consumer-side discipline
//! alone does not. Future readers asking "wouldn't this be simpler
//! without the two-slot structure?" should read the Phase 2F plan-
//! doc (`docs/design/RANDOMX_V2_PHASE2F_PLAN.md` §3.1 Round 2's
//! (d)/(g) rejection) rather than re-proposing the shape.
//!
//! # Caller hand-off Arc-lifetime discipline
//!
//! Consumers should hold `Arc<PreparedCache>` clones only for the
//! duration of the immediate hash computation; long-lived holds
//! extend cache memory residency beyond [`CacheStore`]'s capacity-2
//! bound (each [`crate::PreparedCache`] is ~256 MiB). The
//! recommended pattern is `lookup` (or [`CacheStore::lookup_or_derive`]),
//! use, drop. If a consumer needs to bridge an async boundary, the
//! recommended pattern is to drop the [`std::sync::Arc`] before
//! yielding and re-look-up after the await; this is structurally
//! safer than capturing the Arc in a future. See the Phase 2F
//! plan-doc (`docs/design/RANDOMX_V2_PHASE2F_PLAN.md` §4 F2 and the
//! "Caller hand-off Arc-lifetime discipline" note) for the
//! adversarial finding this pattern defends against.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use crate::PreparedCache;
use crate::Seedhash;

/// Capacity-2 sticky-canonical store for [`PreparedCache`] handles.
///
/// The two slots are:
///
/// - **Canonical** — pinned by [`CacheStore::set_canonical`]; never
///   evicted by [`CacheStore::lookup_or_derive`]. Holds the
///   chain-tip seedhash's cache during normal operation.
/// - **Transient** — displaced by every novel-seedhash
///   [`CacheStore::lookup_or_derive`]. Holds either a probe / alt-tip
///   cache or, after [`CacheStore::set_canonical`] advances the
///   canonical, the previously-canonical cache (preserving it for
///   the duration of any rollback window until the next
///   [`CacheStore::lookup_or_derive`] miss displaces it).
///
/// Construction is via [`CacheStore::new`] (or the
/// [`Default`] impl). The store starts with both slots unset; the
/// FFI shim's lock-ordering discipline (Phase 2F Decision #5)
/// ensures [`CacheStore::set_canonical`] is called before serving
/// production lookups. The cold-start window is bounded to daemon
/// startup.
///
/// # Synchronization shape
///
/// Per Phase 2F §3.1 Round 2: per-slot
/// [`std::sync::RwLock<Option<Arc<PreparedCache>>>`];
/// [`std::sync::Mutex<std::collections::HashMap>`] for the in-flight
/// deduplication map (writes — insert on first call; remove on
/// cleanup-on-publish — and reads are roughly balanced; the critical
/// section is short).
///
/// **Lock-ordering discipline (invariant):** every method that
/// acquires both slot locks acquires them in **canonical-then-
/// transient** order, regardless of read-vs-write mode. This applies
/// to:
///
/// - [`Self::lookup`] — canonical-read, then transient-read; both
///   held across the comparison sequence so the lookup is
///   linearizable against concurrent [`Self::set_canonical`].
/// - [`Self::set_canonical`] — canonical-write, then transient-write
///   (only when an actual swap is needed; the seedhash-equal no-op
///   exits before acquiring transient).
///
/// No method acquires the transient lock before the canonical lock,
/// so there is no deadlock cycle. The publish path inside
/// [`Self::lookup_or_derive`] writes only to the transient slot
/// (transient-write held alone) and to the in-flight map
/// (in-flight-mutex held alone); these are sequential, not nested.
///
/// # In-flight deduplication
///
/// Concurrent [`CacheStore::lookup_or_derive`] calls for the same
/// novel seedhash hit an internal in-flight map keyed by
/// [`Seedhash`]. The first call inserts a derivation slot and
/// performs the Argon2d-512 fill; subsequent calls clone the slot
/// handle and wait on its [`std::sync::Condvar`]. When the first
/// derivation completes, the result is broadcast through the slot
/// (waking all followers), published to the transient slot, and
/// the in-flight-map entry is removed (cleanup-on-publish). The
/// in-flight map holds only currently-derivating seedhashes; size
/// is bounded by the concurrency level, not by total derivations
/// seen.
pub struct CacheStore {
    /// Canonical slot — sticky against eviction by
    /// [`Self::lookup_or_derive`]; only [`Self::set_canonical`] can
    /// replace this slot's content (and only by demoting the prior
    /// canonical to [`Self::transient`]).
    canonical: RwLock<Option<Arc<PreparedCache>>>,
    /// Transient slot — displaced by every
    /// [`Self::lookup_or_derive`] miss when the new derivation has
    /// to be published, and by [`Self::set_canonical`]'s demotion
    /// of the prior canonical.
    transient: RwLock<Option<Arc<PreparedCache>>>,
    /// In-flight derivation map. Each entry's value is a
    /// [`DerivationSlot`] handle on which followers wait while the
    /// leader runs [`PreparedCache::derive`]. Entries are removed
    /// in cleanup-on-publish order (slot result broadcast →
    /// transient publication → in-flight removal) so a follower
    /// waking between broadcast and removal still gets the cached
    /// [`Arc<PreparedCache>`] from the slot rather than re-deriving.
    in_flight: Mutex<HashMap<Seedhash, Arc<DerivationSlot>>>,
}

/// Per-seedhash derivation rendezvous used by the in-flight map.
///
/// One leader thread runs [`PreparedCache::derive`] outside any
/// [`CacheStore`] lock; followers blocked on the same novel
/// seedhash wait on the [`Condvar`] until the leader broadcasts
/// the resulting [`Arc<PreparedCache>`].
struct DerivationSlot {
    /// Set to `Some(prepared)` exactly once by the leader. Followers
    /// wait on [`Self::cv`] while this is `None`.
    inner: Mutex<Option<Arc<PreparedCache>>>,
    /// Notified by [`Self::publish`] after [`Self::inner`] becomes
    /// `Some`. Followers loop on `inner.is_none()` to absorb spurious
    /// wakeups.
    cv: Condvar,
}

impl DerivationSlot {
    fn new() -> DerivationSlot {
        DerivationSlot {
            inner: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    /// Set the derivation result and wake all waiting followers.
    /// Called by the leader exactly once.
    fn publish(&self, result: Arc<PreparedCache>) {
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(result);
        self.cv.notify_all();
    }

    /// Block until [`Self::publish`] runs, then return a clone of
    /// the leader's [`Arc<PreparedCache>`]. The follower never
    /// derives.
    fn wait_for_result(&self) -> Arc<PreparedCache> {
        let mut guard = self.inner.lock().unwrap();
        while guard.is_none() {
            guard = self.cv.wait(guard).unwrap();
        }
        Arc::clone(guard.as_ref().unwrap())
    }
}

/// Internal role assigned by the in-flight-map dispatch step. The
/// leader owns the derivation; followers clone the slot and wait.
enum DerivationRole {
    /// First caller for this seedhash. Must run
    /// [`PreparedCache::derive`], publish the result, populate the
    /// transient slot, and clean up the in-flight entry.
    Leader(Arc<DerivationSlot>),
    /// Subsequent caller for the same in-flight seedhash. Must
    /// wait on the leader's slot and clone the resulting Arc.
    Follower(Arc<DerivationSlot>),
}

impl CacheStore {
    /// Construct an empty store. Both slots start unset; the FFI
    /// shim's lock-ordering discipline (Phase 2F Decision #5)
    /// ensures [`Self::set_canonical`] is called before serving
    /// lookups. The cold-start window is bounded to daemon startup.
    pub fn new() -> CacheStore {
        CacheStore {
            canonical: RwLock::new(None),
            transient: RwLock::new(None),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// Fast-path lookup. Returns `Some(Arc::clone(...))` if
    /// `seedhash` matches the canonical or transient slot, else
    /// `None`. Never derives.
    ///
    /// Separates the fast path (no derivation) from the slow path
    /// ([`Self::lookup_or_derive`]) so a hot-path validator that
    /// knows it should hit canonical can call `lookup` and treat
    /// `None` as an error signal rather than transparently paying
    /// ~150 ms of unexpected derivation cost.
    ///
    /// # Linearizability and lock ordering
    ///
    /// Both slot read guards are acquired before either comparison
    /// runs and held for the duration of the comparison sequence.
    /// This makes the lookup linearizable against concurrent
    /// [`Self::set_canonical`] calls: a `set_canonical` cannot
    /// promote an entry from transient to canonical (or demote
    /// canonical to transient) between this method's two slot
    /// inspections, so a `seedhash` that is present in either slot
    /// at function entry is guaranteed to be observed.
    ///
    /// The acquisition order — **canonical-read first, transient-
    /// read second** — matches [`Self::set_canonical`]'s
    /// canonical-write-then-transient-write order, eliminating any
    /// deadlock cycle. Concurrent `lookup` callers do not block
    /// each other; `lookup` blocks only when a writer holds (or is
    /// queued for) one of the slot locks, which is bounded by the
    /// `set_canonical` / publish-on-derive critical sections (each
    /// O(register-write)).
    ///
    /// The pre-fix behavior — releasing the canonical guard before
    /// acquiring the transient guard — opened a transient→canonical
    /// promotion race in which a concurrent `set_canonical` could
    /// move the requested entry between the two checks; this method
    /// now closes that window. See PR #72 NF2.
    pub fn lookup(&self, seedhash: &Seedhash) -> Option<Arc<PreparedCache>> {
        let canonical = self.canonical.read().unwrap();
        let transient = self.transient.read().unwrap();
        if let Some(p) = canonical.as_ref() {
            if p.seedhash() == seedhash {
                return Some(Arc::clone(p));
            }
        }
        if let Some(p) = transient.as_ref() {
            if p.seedhash() == seedhash {
                return Some(Arc::clone(p));
            }
        }
        None
    }

    /// Slow-path lookup: returns the cache for `seedhash`, deriving
    /// on miss.
    ///
    /// Concurrent calls for the same novel `seedhash` share one
    /// in-flight derivation per the in-flight-deduplication shape
    /// pinned in Phase 2F §3.1 Round 2; only one
    /// [`PreparedCache::derive`] (Argon2d-512 fill) runs. On
    /// derivation completion the result is published into the
    /// transient slot and returned. The in-flight-map entry is
    /// dropped immediately on publish (cleanup-on-publish; see
    /// Phase 2F §4 F4).
    ///
    /// # Cost
    ///
    /// - Hit on canonical or transient: a few hundred nanoseconds
    ///   (two [`std::sync::RwLock`] read acquisitions plus
    ///   [`Seedhash`] equality).
    /// - Miss with no contender: ~150–200 ms ([`PreparedCache::derive`]
    ///   cost — dominated by the 256 MiB Argon2d-512 fill).
    /// - Miss with contenders: same ~150–200 ms wall time across
    ///   all contenders; only the leader pays CPU.
    pub fn lookup_or_derive(&self, seedhash: &Seedhash) -> Arc<PreparedCache> {
        if let Some(p) = self.lookup(seedhash) {
            return p;
        }

        let role = {
            let mut in_flight = self.in_flight.lock().unwrap();
            if let Some(p) = self.lookup(seedhash) {
                return p;
            }
            match in_flight.get(seedhash) {
                Some(slot) => DerivationRole::Follower(Arc::clone(slot)),
                None => {
                    let slot = Arc::new(DerivationSlot::new());
                    in_flight.insert(*seedhash, Arc::clone(&slot));
                    DerivationRole::Leader(slot)
                }
            }
        };

        match role {
            DerivationRole::Leader(slot) => {
                let prepared = Arc::new(PreparedCache::derive(*seedhash));
                slot.publish(Arc::clone(&prepared));
                {
                    let mut t = self.transient.write().unwrap();
                    *t = Some(Arc::clone(&prepared));
                }
                {
                    let mut in_flight = self.in_flight.lock().unwrap();
                    in_flight.remove(seedhash);
                }
                prepared
            }
            DerivationRole::Follower(slot) => slot.wait_for_result(),
        }
    }

    /// Advance the canonical slot to hold `prepared`.
    ///
    /// Semantics:
    ///
    /// - The previous canonical (if any) is demoted to the
    ///   transient slot, evicting the prior transient occupant
    ///   from the slot. The evicted occupant's
    ///   [`Arc<PreparedCache>`] clones held in consumer code stay
    ///   alive until those clones drop; the underlying cache lives
    ///   as long as any clone references it, regardless of slot
    ///   occupancy.
    /// - The new `prepared` lives in the canonical slot; it is
    ///   non-evictable for as long as it is canonical.
    /// - If `prepared.seedhash()` already matches the existing
    ///   canonical's seedhash, the call is a no-op (canonical and
    ///   transient slots both unchanged).
    ///
    /// The argument is the bundled `Arc<PreparedCache>`, not a
    /// seedhash + cache pair. The caller obtains it via
    /// [`Self::lookup_or_derive`] (or by direct
    /// [`PreparedCache::derive`] outside the store).
    ///
    /// # Lock ordering
    ///
    /// Acquires the canonical write lock first, then the transient
    /// write lock. No other [`CacheStore`] method holds the
    /// transient write lock while waiting for the canonical write
    /// lock, so there is no deadlock cycle.
    pub fn set_canonical(&self, prepared: Arc<PreparedCache>) {
        let mut canonical = self.canonical.write().unwrap();
        if let Some(current) = canonical.as_ref() {
            if current.seedhash() == prepared.seedhash() {
                return;
            }
        }
        let mut transient = self.transient.write().unwrap();
        let prior = canonical.replace(prepared);
        *transient = prior;
    }
}

impl Default for CacheStore {
    fn default() -> CacheStore {
        CacheStore::new()
    }
}

#[cfg(test)]
mod tests {
    //! Phase 2F §6.1 Round 3 unit tests for [`CacheStore`]. Test
    //! IDs T-CS-1..11 map to the rows of the §3.1 Round 2 11-row
    //! pre/post state-transition table; each test's
    //! `lookup(...).is_some()` / `is_none()` checks reproduce the
    //! corresponding row's post-state.
    //!
    //! Test fixtures use real [`PreparedCache::derive`] — no stub
    //! `Cache` constructor exists in the crate at this PR (the
    //! Phase 2c §14 Round 0 R0-D5 disposition dropped
    //! `Cache::from_raw`). Each [`PreparedCache::derive`] call costs
    //! ~150–200 ms in release mode; each test that calls
    //! [`CacheStore::lookup_or_derive`] for a novel seedhash incurs
    //! that cost once per unique seedhash. Tests that need
    //! externally-constructed `Arc<PreparedCache>` instances reuse
    //! a `OnceLock`-backed fixture per [Phase 2F §6.1 Round 3] to
    //! avoid paying the derivation cost twice for the same
    //! seedhash. Test ordering is per-test-isolated (each test
    //! constructs its own [`CacheStore`]; no shared store state).
    //!
    //! [Phase 2F §6.1 Round 3]: ../../../docs/design/RANDOMX_V2_PHASE2F_PLAN.md

    use super::{CacheStore, DerivationSlot};
    use crate::{PreparedCache, Seedhash};
    use std::sync::{Arc, OnceLock};
    use std::thread;

    /// Distinct seedhash literals for slot-behavior tests. Each
    /// distinct value triggers one [`PreparedCache::derive`] inside
    /// the store under test.
    fn seedhash_a() -> Seedhash {
        Seedhash::from_bytes([0xa1; 32])
    }
    fn seedhash_b() -> Seedhash {
        Seedhash::from_bytes([0xb2; 32])
    }
    fn seedhash_c() -> Seedhash {
        Seedhash::from_bytes([0xc3; 32])
    }
    fn seedhash_d() -> Seedhash {
        Seedhash::from_bytes([0xd4; 32])
    }
    fn seedhash_novel() -> Seedhash {
        Seedhash::from_bytes([0x4e; 32])
    }

    /// Single shared `Arc<PreparedCache>` for the seedhash literal
    /// `0x42; 32`. Derivation cost is paid once across the type-
    /// level tests T-CS-10 / T-CS-11 that need a pre-constructed
    /// bundle to feed into [`CacheStore::set_canonical`] /
    /// [`CacheStore::lookup`]. Stored in a [`OnceLock`] inside the
    /// `mod tests` block so the static is `cfg(test)`-gated and
    /// the §3.6 R1-E1 Pattern A grep does not match (the gate
    /// fires only at module-level non-test scope).
    fn shared_42_prepared() -> Arc<PreparedCache> {
        static ONCE: OnceLock<Arc<PreparedCache>> = OnceLock::new();
        Arc::clone(
            ONCE.get_or_init(|| Arc::new(PreparedCache::derive(Seedhash::from_bytes([0x42; 32])))),
        )
    }

    // ---- T-CS-1 -------------------------------------------------

    #[test]
    fn cachestore_canonical_survives_3way_interleave() {
        // F1 anti-DoS test: rows 5, 6 of §3.1 Round 2 plus an
        // extension to seedhash D. After
        // `set_canonical(la(A)); la(B); la(C); la(D);` the canonical
        // slot still holds A, the transient slot holds D, and B/C
        // have been displaced from slot occupancy.
        let cs = CacheStore::new();
        let pa = cs.lookup_or_derive(&seedhash_a());
        cs.set_canonical(pa);
        let _pb = cs.lookup_or_derive(&seedhash_b());
        let _pc = cs.lookup_or_derive(&seedhash_c());
        let _pd = cs.lookup_or_derive(&seedhash_d());
        assert!(cs.lookup(&seedhash_a()).is_some());
        assert!(cs.lookup(&seedhash_d()).is_some());
        assert!(cs.lookup(&seedhash_b()).is_none());
        assert!(cs.lookup(&seedhash_c()).is_none());
    }

    // ---- T-CS-2 -------------------------------------------------

    #[test]
    fn cachestore_no_canonical_evicts_in_transient() {
        // R1-D2 #2 degenerate-case test: with no `set_canonical`
        // call ever made, both slots act as a single-entry transient.
        // After `la(A); la(B);` only B is in the transient; A is
        // gone.
        let cs = CacheStore::new();
        let _pa = cs.lookup_or_derive(&seedhash_a());
        let _pb = cs.lookup_or_derive(&seedhash_b());
        assert!(cs.lookup(&seedhash_a()).is_none());
        assert!(cs.lookup(&seedhash_b()).is_some());
    }

    // ---- T-CS-3 -------------------------------------------------

    #[test]
    fn cachestore_canonical_advance_demotes_prior() {
        // R1-D2 #3 advance test (row 7): advancing canonical from A
        // to B demotes A to the transient slot (preserving A for
        // any rollback window); a subsequent novel `la(C)` then
        // displaces A from the transient.
        let cs = CacheStore::new();
        let pa = cs.lookup_or_derive(&seedhash_a());
        cs.set_canonical(pa);
        let pb = cs.lookup_or_derive(&seedhash_b());
        cs.set_canonical(pb);
        assert!(cs.lookup(&seedhash_a()).is_some());
        assert!(cs.lookup(&seedhash_b()).is_some());

        let _pc = cs.lookup_or_derive(&seedhash_c());
        assert!(cs.lookup(&seedhash_a()).is_none());
        assert!(cs.lookup(&seedhash_b()).is_some());
        assert!(cs.lookup(&seedhash_c()).is_some());
    }

    // ---- T-CS-4 -------------------------------------------------

    #[test]
    fn cachestore_set_canonical_noop_on_canonical_match() {
        // No-op identity test (row 8): re-advancing the canonical
        // to the seedhash that already occupies it leaves both
        // slots unchanged; the transient occupant survives.
        let cs = CacheStore::new();
        let pa = cs.lookup_or_derive(&seedhash_a());
        cs.set_canonical(Arc::clone(&pa));
        let _pb = cs.lookup_or_derive(&seedhash_b());
        cs.set_canonical(pa);
        assert!(cs.lookup(&seedhash_a()).is_some());
        assert!(cs.lookup(&seedhash_b()).is_some());
    }

    // ---- T-CS-5 -------------------------------------------------

    #[test]
    fn cachestore_lookup_returns_arc_clone() {
        // Generic invariant: every successful `lookup` /
        // `lookup_or_derive` returns an `Arc` clone. The slot's
        // own clone keeps the cache alive while consumer-held
        // clones come and go; the strong-count rises and falls
        // accordingly.
        let cs = CacheStore::new();
        let pa = cs.lookup_or_derive(&seedhash_a());
        // Slot holds one clone (transient), caller holds one.
        assert_eq!(Arc::strong_count(&pa), 2);
        let pa2 = cs.lookup(&seedhash_a()).unwrap();
        // Now slot + caller's `pa` + caller's `pa2` = 3.
        assert_eq!(Arc::strong_count(&pa), 3);
        drop(pa2);
        // Caller dropped their second clone; back to 2.
        assert_eq!(Arc::strong_count(&pa), 2);
    }

    // ---- T-CS-6 -------------------------------------------------

    #[test]
    fn cachestore_thread_safety_smoke() {
        // Generic invariant: alternating `lookup` /
        // `lookup_or_derive` / `set_canonical` calls across two
        // threads against a shared `Arc<CacheStore>`. The test
        // passes if no panic, no deadlock, and the canonical slot
        // survives the interleave. Iteration count tuned for
        // release-mode runtime (each iteration may incur a
        // ~150 ms `PreparedCache::derive` if the seedhash is
        // novel; we keep the seedhash set small so most iterations
        // hit the slot).
        let cs = Arc::new(CacheStore::new());
        // Pre-derive A and pin it canonical so subsequent lookups
        // hit the slot rather than re-deriving.
        let pa = cs.lookup_or_derive(&seedhash_a());
        cs.set_canonical(Arc::clone(&pa));

        let cs1 = Arc::clone(&cs);
        let cs2 = Arc::clone(&cs);
        let pa_for_t1 = Arc::clone(&pa);

        let h1 = thread::spawn(move || {
            for _ in 0..100 {
                let _ = cs1.lookup(&seedhash_a());
                let _ = cs1.lookup_or_derive(&seedhash_a());
                cs1.set_canonical(Arc::clone(&pa_for_t1));
            }
        });
        let h2 = thread::spawn(move || {
            for _ in 0..100 {
                let _ = cs2.lookup(&seedhash_a());
                let _ = cs2.lookup_or_derive(&seedhash_a());
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();

        // Canonical slot still holds A.
        assert!(cs.lookup(&seedhash_a()).is_some());
    }

    // ---- T-CS-7 -------------------------------------------------

    #[test]
    fn cachestore_thundering_herd_dedup() {
        // F3 thundering-herd test (row 11): two concurrent
        // `lookup_or_derive` calls for the same novel seedhash
        // share one Argon2d fill and receive `Arc`-identical
        // results.
        let cs = Arc::new(CacheStore::new());
        let cs1 = Arc::clone(&cs);
        let cs2 = Arc::clone(&cs);
        let h1 = thread::spawn(move || cs1.lookup_or_derive(&seedhash_novel()));
        let h2 = thread::spawn(move || cs2.lookup_or_derive(&seedhash_novel()));
        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();
        assert!(Arc::ptr_eq(&r1, &r2));
    }

    // ---- T-CS-8 -------------------------------------------------

    #[test]
    fn cachestore_inflight_cleanup_on_publish() {
        // F4 cleanup-on-publish test (row 11): after
        // `lookup_or_derive(&A)` completes, the in-flight map is
        // empty for seedhash A. Uses `pub(crate)` access to the
        // private `in_flight` field per the §6.1 Round 3 white-
        // box-test discipline.
        let cs = CacheStore::new();
        let _pa = cs.lookup_or_derive(&seedhash_a());
        assert!(cs.in_flight.lock().unwrap().is_empty());
    }

    // ---- T-CS-9 -------------------------------------------------

    #[test]
    fn cachestore_concurrent_derivation_determinism() {
        // F5 concurrent-derivation race test: two threads each
        // construct `PreparedCache::derive(SAME_SEEDHASH)` *outside*
        // the CacheStore (so the in-flight dedup does not apply).
        // The resulting caches must produce byte-identical first
        // dataset items, demonstrating `Cache::derive` determinism
        // independent of in-flight-dedup.
        let h1 = thread::spawn(|| PreparedCache::derive(seedhash_a()));
        let h2 = thread::spawn(|| PreparedCache::derive(seedhash_a()));
        let p1 = h1.join().unwrap();
        let p2 = h2.join().unwrap();
        // Compare the first 64 bytes of cache memory via
        // `derive_item(0)` — both caches should have produced the
        // same dataset item byte-for-byte.
        let item1 = p1.cache_ref().derive_item(0);
        let item2 = p2.cache_ref().derive_item(0);
        assert_eq!(item1, item2);
    }

    // ---- T-CS-10 ------------------------------------------------

    #[test]
    fn cachestore_set_canonical_takes_arc_prepared() {
        // Round 2 type-shape: `set_canonical` accepts
        // `Arc<PreparedCache>`, not a seedhash + cache pair. The
        // assignment compiles iff the type signature is correct.
        let cs = CacheStore::new();
        let pa: Arc<PreparedCache> = shared_42_prepared();
        cs.set_canonical(pa);
        assert!(cs.lookup(&Seedhash::from_bytes([0x42; 32])).is_some());
    }

    // ---- T-CS-11 ------------------------------------------------

    #[test]
    fn cachestore_lookup_returns_typed_seedhash() {
        // Round 2 type-shape: `lookup` takes `&Seedhash`, not
        // `&[u8; 32]`. The call compiles iff the newtype is the
        // accepted parameter type at the call site.
        let cs = CacheStore::new();
        let pa: Arc<PreparedCache> = shared_42_prepared();
        cs.set_canonical(pa);
        let s = Seedhash::from_bytes([0x42; 32]);
        assert!(cs.lookup(&s).is_some());
        // And a non-matching seedhash returns None.
        let other = Seedhash::from_bytes([0x99; 32]);
        assert!(cs.lookup(&other).is_none());
    }

    // ---- T-CS-12 ------------------------------------------------

    #[test]
    fn cachestore_lookup_linearizable_under_canonical_swap() {
        // PR #72 NF2 regression test: the buggy `lookup`
        // implementation released the canonical read guard before
        // acquiring the transient read guard, opening a race window
        // in which a concurrent `set_canonical` could promote an
        // entry from transient to canonical (and demote the prior
        // canonical to transient) between the two inspections. A
        // `lookup(&T)` straddling such a swap could observe
        // canonical=Some(prior) (released) → transient=Some(prior)
        // (after the demote, the prior canonical is now in
        // transient) and return `None` despite the requested entry
        // being live in the canonical slot the entire time.
        //
        // **Setup.** Both slots populated with distinct prepared
        // caches:
        //
        //   1. `lookup_or_derive(&s_a)` derives `p_a` into transient.
        //   2. `set_canonical(p_a)` promotes `p_a` to canonical
        //      (transient resets to `None` because the prior canonical
        //      was `None`, which is documented as "evicts the prior
        //      transient occupant" — `p_a`'s slot binding moves from
        //      transient to canonical).
        //   3. `lookup_or_derive(&s_b)` derives `p_b` into transient.
        //
        //   Final pre-loop state: canonical = Some(p_a), transient =
        //   Some(p_b). Both `s_a` and `s_b` are observable via
        //   `lookup`.
        //
        // **Loop invariant.** Each writer iteration alternates
        // `set_canonical(p_a) / set_canonical(p_b)`; every call swaps
        // the slots — `p_a`/`p_b` are always present in *some* slot
        // at every observable moment. A linearizable `lookup` must
        // always find them.
        //
        // With the buggy implementation this test fails
        // probabilistically under thread interleaving; with the
        // fixed implementation (both read guards held across the
        // comparison sequence) it passes deterministically because
        // a concurrent `set_canonical` cannot interleave between the
        // two slot reads.
        //
        // **Cost.** Two `PreparedCache::derive` calls (~150–200 ms
        // each) outside the timed contention loop; the loop itself
        // is 2,000 × (2 swaps + 4 lookups) of microsecond-scale
        // operations.
        let cs = Arc::new(CacheStore::new());
        let s_a = seedhash_a();
        let s_b = seedhash_b();
        // Step 1: derive p_a (lands in transient).
        let p_a = cs.lookup_or_derive(&s_a);
        // Step 2: promote p_a to canonical (transient evicts to None).
        cs.set_canonical(Arc::clone(&p_a));
        // Step 3: derive p_b into transient. Now both slots populated.
        let p_b = cs.lookup_or_derive(&s_b);
        // Sanity-check the pre-loop state: both seedhashes observable.
        assert!(cs.lookup(&s_a).is_some());
        assert!(cs.lookup(&s_b).is_some());

        let cs_writer = Arc::clone(&cs);
        let p_a_for_writer = Arc::clone(&p_a);
        let p_b_for_writer = Arc::clone(&p_b);
        let writer = thread::spawn(move || {
            for _ in 0..2_000 {
                cs_writer.set_canonical(Arc::clone(&p_b_for_writer));
                cs_writer.set_canonical(Arc::clone(&p_a_for_writer));
            }
        });

        let cs_reader = Arc::clone(&cs);
        let reader = thread::spawn(move || {
            for _ in 0..2_000 {
                assert!(
                    cs_reader.lookup(&s_a).is_some(),
                    "lookup(&s_a) returned None during canonical swap loop \
                     — non-linearizable lookup (PR #72 NF2)"
                );
                assert!(
                    cs_reader.lookup(&s_b).is_some(),
                    "lookup(&s_b) returned None during canonical swap loop \
                     — non-linearizable lookup (PR #72 NF2)"
                );
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    }

    // ---- DerivationSlot internal coverage -----------------------

    #[test]
    fn derivation_slot_publish_then_wait_returns_clone() {
        // White-box: `DerivationSlot::publish` then
        // `wait_for_result` returns the published `Arc`.
        let slot = DerivationSlot::new();
        let prepared = shared_42_prepared();
        slot.publish(Arc::clone(&prepared));
        let observed = slot.wait_for_result();
        assert!(Arc::ptr_eq(&prepared, &observed));
    }

    #[test]
    fn derivation_slot_wait_blocks_until_publish() {
        // White-box: a follower thread blocks on
        // `wait_for_result` until the leader thread publishes.
        let slot = Arc::new(DerivationSlot::new());
        let slot_follower = Arc::clone(&slot);
        let h = thread::spawn(move || slot_follower.wait_for_result());
        // Give the follower thread a chance to enter the wait.
        thread::sleep(std::time::Duration::from_millis(10));
        let prepared = shared_42_prepared();
        slot.publish(Arc::clone(&prepared));
        let observed = h.join().unwrap();
        assert!(Arc::ptr_eq(&prepared, &observed));
    }
}
