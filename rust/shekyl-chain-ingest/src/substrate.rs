// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production [`Substrate`]: a wall clock and RandomX v2 (RD-Q3).
//!
//! `shekyl-chain-rules` asks the world two things a rule may not fetch for
//! itself — what time it is (CEN-C1) and what RandomX makes of a PoW
//! preimage under a seed (CEN-D2) — and until this crate only mocks
//! answered. [`ChainSubstrate`] answers with `std::time` and
//! `shekyl-pow-randomx`'s production surface.
//!
//! # RandomX, as ruled
//!
//! - **`compute_hash` per call over a shared [`CacheStore`]** (RD-F14). The
//!   store holds two prepared caches — the canonical epoch and one
//!   transient — and `lookup_or_derive` fills a missing one under a leader
//!   lock, so N `form` workers sharing one `Arc<CacheStore>` derive each
//!   epoch's 256 MiB cache once. The bench-only `VmStatePool` is not a
//!   production API and is not used.
//! - **The seed is the rule's.** `longhash(blob, seed)` computes under the
//!   seed CEN-D3 chose (`seedheight(h)`'s block id); this type never picks
//!   one. Swapping the canonical slot at an epoch boundary
//!   ([`ChainSubstrate::caches`] → `set_canonical`) is the schedule's job,
//!   upstream.
//! - **Never the JIT** (§1.3): replay validates with the hasher production
//!   validates with, or it tests a different daemon.
//! - **Cache-only, measured** (RD-F11): the dataset mode is unbuilt
//!   pending the number this pipeline's metrics sink will produce.
//!
//! # Faults
//!
//! The clock can fail (a system time before the epoch); the hasher cannot —
//! `compute_hash` is total over its inputs and `lookup_or_derive` derives
//! rather than refuses — so [`SubstrateFault`] has one arm today. A fault is
//! returned in `form`'s outer position and is **terminal for the run**
//! (§1.1's supervision table): a verifier that cannot compute is the node's
//! outage, never the block's verdict.

use core::fmt;
use std::sync::Arc;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use shekyl_chain_rules::Substrate;
use shekyl_pow_randomx::{compute_hash, CacheOutcome, CacheStore, Seedhash};
use shekyl_types::{BlockHash, PowHash, Timestamp};

use crate::metrics::Metrics;

/// Why the clock could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClockFault {
    /// The system clock reads before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    BeforeEpoch,
}

/// A wall clock, injectable so a test can fix the instant.
pub trait Clock {
    /// Now, in Unix seconds.
    ///
    /// # Errors
    ///
    /// [`ClockFault`] when the clock cannot be read.
    fn now(&self) -> Result<Timestamp, ClockFault>;
}

/// `std::time::SystemTime`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<Timestamp, ClockFault> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| Timestamp::from_raw(d.as_secs()))
            .map_err(|_| ClockFault::BeforeEpoch)
    }
}

/// What the production substrate can fail with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubstrateFault {
    /// The clock (CEN-C1's operand) could not be read.
    #[error(transparent)]
    Clock(#[from] ClockFault),
}

/// Pinning the canonical seed epoch (RD-F18).
///
/// `CacheStore` holds two prepared caches — canonical and transient — and
/// derives on every miss. A driver that never pins leaves both live seeds
/// of a lag window fighting over the one transient slot, so each switch
/// between them is a fresh 256 MiB fill: the first real run re-derived at
/// window 16 on a 301-block chain with two seeds. The pipeline pins the
/// claimed seed as canonical whenever it changes, before the blocks under
/// it are formed. The mock substrate has nothing to pin.
pub trait EpochPin {
    /// Make `seed`'s cache the canonical one, deriving it if needed.
    fn pin_epoch(&self, seed: &BlockHash);
}

#[cfg(test)]
impl EpochPin for shekyl_chain_rules::harness::MockSubstrate {
    fn pin_epoch(&self, _seed: &BlockHash) {}
}

impl<C: Clock> EpochPin for ChainSubstrate<C> {
    fn pin_epoch(&self, seed: &BlockHash) {
        let seedhash = Seedhash::from_bytes(seed.to_bytes());
        let started = Instant::now();
        let (prepared, outcome) = self.caches.lookup_or_derive_reporting(&seedhash);
        match outcome {
            CacheOutcome::Derived => self.metrics.derived(started.elapsed()),
            CacheOutcome::Waited => self.metrics.waited(started.elapsed()),
            CacheOutcome::Hit => {}
        }
        self.caches.set_canonical(prepared);
    }
}

/// The production substrate (module docs).
pub struct ChainSubstrate<C: Clock = SystemClock> {
    caches: Arc<CacheStore>,
    clock: C,
    metrics: Arc<Metrics>,
}

// `CacheStore` is not `Debug` (two 256 MiB caches behind locks have no
// useful rendering); say what a substrate is rather than what it holds.
impl<C: Clock + fmt::Debug> fmt::Debug for ChainSubstrate<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainSubstrate")
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl ChainSubstrate<SystemClock> {
    /// Over `caches`, reading the system clock, recording into `metrics`.
    #[must_use]
    pub fn new(caches: Arc<CacheStore>, metrics: Arc<Metrics>) -> Self {
        Self::with_clock(caches, SystemClock, metrics)
    }
}

impl<C: Clock> ChainSubstrate<C> {
    /// Over `caches`, reading `clock`, recording into `metrics`.
    #[must_use]
    pub const fn with_clock(caches: Arc<CacheStore>, clock: C, metrics: Arc<Metrics>) -> Self {
        Self {
            caches,
            clock,
            metrics,
        }
    }

    /// The shared cache store, for the schedule that pins the canonical
    /// epoch (`set_canonical`) at a seed boundary.
    #[must_use]
    pub fn caches(&self) -> &Arc<CacheStore> {
        &self.caches
    }

    /// The sink this substrate records into (RD-F11).
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
}

impl<C: Clock> Substrate for ChainSubstrate<C> {
    type Fault = SubstrateFault;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(self.clock.now()?)
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault> {
        let seedhash = Seedhash::from_bytes(seed.to_bytes());
        // A derive is the 256 MiB fill and is timed apart from the hash
        // (metrics module docs). The store says how it served the call:
        // only a `Derived` outcome is a derivation — a `Waited` caller spent
        // the leader's wall time and did none of the work, and counting it
        // overstated derives 32× on the first real run (RD-F18).
        let started = Instant::now();
        let (prepared, outcome) = self.caches.lookup_or_derive_reporting(&seedhash);
        match outcome {
            CacheOutcome::Derived => self.metrics.derived(started.elapsed()),
            CacheOutcome::Waited => self.metrics.waited(started.elapsed()),
            CacheOutcome::Hit => {}
        }
        let hash = self
            .metrics
            .timed_hash(|| compute_hash(&prepared, pow_blob));
        Ok(PowHash::from_bytes(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_pow_randomx::PreparedCache;

    struct FixedClock(Timestamp);

    impl Clock for FixedClock {
        fn now(&self) -> Result<Timestamp, ClockFault> {
            Ok(self.0)
        }
    }

    struct BrokenClock;

    impl Clock for BrokenClock {
        fn now(&self) -> Result<Timestamp, ClockFault> {
            Err(ClockFault::BeforeEpoch)
        }
    }

    #[test]
    fn the_clock_is_the_injected_one_and_its_fault_is_the_substrates() {
        let caches = Arc::new(CacheStore::new());
        let fixed = ChainSubstrate::with_clock(
            Arc::clone(&caches),
            FixedClock(Timestamp::from_raw(7)),
            Arc::new(Metrics::new()),
        );
        assert_eq!(fixed.local_clock(), Ok(Timestamp::from_raw(7)));
        let broken = ChainSubstrate::with_clock(caches, BrokenClock, Arc::new(Metrics::new()));
        assert_eq!(
            broken.local_clock(),
            Err(SubstrateFault::Clock(ClockFault::BeforeEpoch))
        );
    }

    #[test]
    fn the_system_clock_reads_after_the_epoch() {
        let now = SystemClock.now().expect("system time is after 1970");
        assert!(now > Timestamp::from_raw(1_700_000_000));
    }

    #[test]
    fn longhash_is_compute_hash_under_the_seeds_cache_and_the_cache_is_shared() {
        // One derive per seed across the shared store: the second call and
        // a second substrate over the same Arc both find the cache.
        let caches = Arc::new(CacheStore::new());
        let seed = BlockHash::from_bytes([0x5e; 32]);
        let blob = b"pow preimage under test";
        let metrics = Arc::new(Metrics::new());
        let a = ChainSubstrate::new(Arc::clone(&caches), Arc::clone(&metrics));
        let got = a.longhash(blob, &seed).expect("hasher is total");
        let after_one = metrics.snapshot();
        assert_eq!(
            (after_one.hashes, after_one.cache_derives),
            (1, 1),
            "first use derives"
        );

        let expected = compute_hash(
            &PreparedCache::derive(Seedhash::from_bytes(seed.to_bytes())),
            blob,
        );
        assert_eq!(got, PowHash::from_bytes(expected));

        let seedhash = Seedhash::from_bytes(seed.to_bytes());
        assert!(
            caches.lookup(&seedhash).is_some(),
            "the derive landed in the shared store"
        );
        let b = ChainSubstrate::new(caches, Arc::clone(&metrics));
        assert_eq!(b.longhash(blob, &seed).expect("total"), got);
        let after_two = metrics.snapshot();
        assert_eq!(
            (after_two.hashes, after_two.cache_derives),
            (2, 1),
            "the second hash found the cache"
        );
    }
}
