// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production [`Substrate`]: RandomX verification and the system clock
//! (`DRS_E2_REPLAY_DRIVER.md` RD-Q3).
//!
//! Until this type existed only mocks implemented the trait. This is the
//! one implementation every Shekyl validator runs — the replay driver, the
//! live daemon, the wallet's own checks — and it is a **thin adapter** over
//! `shekyl-pow-randomx`'s verifier surface: `CacheStore::lookup_or_derive`
//! for the seed's [`PreparedCache`] (the daemon's two-epoch cache, so a
//! replay crossing a seed boundary swaps caches the way the daemon does)
//! and `compute_hash` for the longhash. Never the mining JIT (§1.3); never
//! `VmStatePool`, which is bench scaffolding (RD-F14). Parallel formation
//! is N workers each holding a clone of this substrate — the cache store is
//! shared behind its own `Arc`s, the scratchpad is per call.
//!
//! # Faults
//!
//! `compute_hash` cannot fail once the cache exists, and `lookup_or_derive`
//! derives on a miss (a 256 MiB Argon2d fill; seconds on the provisioning
//! floor, rule 76) rather than failing. The one thing that can fail is the
//! clock — a system time before the Unix epoch — and it is a fault, never a
//! timestamp of zero.
//!
//! # Measurement
//!
//! This is the first workload that runs RandomX verification at volume over
//! a real chain, so the dataset-mode question (`RANDOMX_V2_RUST.md` §9,
//! measure-first) is answered by numbers this pipeline emits (RD-F11). The
//! metrics sink owns the timing; this adapter owns nothing but the calls.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use shekyl_chain_rules::Substrate;
use shekyl_pow_randomx::{compute_hash, CacheOutcome, CacheStore, Seedhash};
use shekyl_types::{BlockHash, PowHash, Timestamp};

use crate::metrics::Metrics;

/// What the production substrate could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstrateFault {
    /// The system clock reads before the Unix epoch. A timestamp cannot be
    /// made of that; the FTL rule (CEN-C1) is not asked.
    ClockBeforeEpoch,
}

impl core::fmt::Display for SubstrateFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClockBeforeEpoch => f.write_str(
                "the system clock reads before the Unix epoch; no local time for the FTL rule",
            ),
        }
    }
}

impl core::error::Error for SubstrateFault {}

/// RandomX through the verifier's cache path, and the system clock.
#[derive(Clone, Default)]
pub struct ProductionSubstrate {
    caches: Arc<CacheStore>,
    /// The RandomX measurement sink (RD-F11); shared with the pipeline,
    /// which times each block's `form` into the same counters.
    metrics: Arc<Metrics>,
}

impl ProductionSubstrate {
    /// A substrate over a fresh cache store. Callers that form in parallel
    /// clone the value: the store is shared, derivation is de-duplicated
    /// inside it, and each worker's `compute_hash` gets its own scratchpad.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Share an existing cache store (the daemon's, at E3).
    #[must_use]
    pub fn over(caches: Arc<CacheStore>) -> Self {
        Self {
            caches,
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Over `caches`, recording into `metrics`.
    #[must_use]
    pub const fn with_metrics(caches: Arc<CacheStore>, metrics: Arc<Metrics>) -> Self {
        Self { caches, metrics }
    }

    /// The sink this substrate records into.
    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
}

/// Pinning the canonical seed epoch (RD-F20).
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

impl EpochPin for ProductionSubstrate {
    fn pin_epoch(&self, seed: &BlockHash) {
        let seedhash = Seedhash::from_bytes(*seed.as_bytes());
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

impl Substrate for ProductionSubstrate {
    type Fault = SubstrateFault;

    fn local_clock(&self) -> Result<Timestamp, SubstrateFault> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SubstrateFault::ClockBeforeEpoch)?;
        Ok(Timestamp::from_raw(since_epoch.as_secs()))
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, SubstrateFault> {
        let seedhash = Seedhash::from_bytes(*seed.as_bytes());
        // A derive is the 256 MiB fill and is timed apart from the hash
        // (metrics module docs). The store says how it served the call:
        // only a `Derived` outcome is a derivation — a `Waited` caller spent
        // the leader's wall time and did none of the work (RD-F20).
        let started = Instant::now();
        let (cache, outcome) = self.caches.lookup_or_derive_reporting(&seedhash);
        match outcome {
            CacheOutcome::Derived => self.metrics.derived(started.elapsed()),
            CacheOutcome::Waited => self.metrics.waited(started.elapsed()),
            CacheOutcome::Hit => {}
        }
        let hash = self.metrics.timed_hash(|| compute_hash(&cache, pow_blob));
        Ok(PowHash::from_bytes(hash))
    }
}

#[cfg(test)]
#[path = "substrate_tests.rs"]
mod substrate_tests;
