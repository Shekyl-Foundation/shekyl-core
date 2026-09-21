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
use std::time::{SystemTime, UNIX_EPOCH};

use shekyl_chain_rules::Substrate;
use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};
use shekyl_types::{BlockHash, PowHash, Timestamp};

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
        Self { caches }
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
        let cache = self.caches.lookup_or_derive(&seedhash);
        Ok(PowHash::from_bytes(compute_hash(&cache, pow_blob)))
    }
}

#[cfg(test)]
#[path = "substrate_tests.rs"]
mod substrate_tests;
