// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a hashing job's substrate can fail with, and the substrate a
//! switch re-judges through.
//!
//! The production substrate is not a type a caller holds: it exists inside
//! one hashing job, over the cache that job borrowed
//! ([`ProductionPow`](crate::pow::ProductionPow), `RANDOMX_CACHE_ACTOR.md`
//! §5.3). Its longhash hashes under the job's seed and no other.
//!
//! # Faults
//!
//! `compute_hash` cannot fail once the job holds its cache, and a job
//! always gets its cache (HA-R1). What is left:
//!
//! - the clock: a system time before the Unix epoch, never a timestamp of
//!   zero;
//! - a longhash asked for a seed other than the job's
//!   ([`SubstrateFault::SeedNotLent`]): a defect in the caller, which
//!   named one seed to the job and another to the rule. It is a fault and
//!   never a verdict: a valid block refused for it would split the chain;
//! - a stop that reached a hash ([`SubstrateFault::Stopped`]): not a fault
//!   at all, and never logged as one.

use shekyl_chain_rules::Substrate;
use shekyl_types::{BlockHash, PowHash, Timestamp};

/// What a hashing job's substrate could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstrateFault {
    /// The system clock reads before the Unix epoch. A timestamp cannot be
    /// made of that; the FTL rule (CEN-C1) is not asked.
    ClockBeforeEpoch,
    /// `longhash` was asked for `asked` where no cache for it was lent:
    /// inside a job that borrowed `lent`'s, or where no job was asked for
    /// because every block's hash was on record. A job hashes under its
    /// own seed only, and nothing is built here.
    SeedNotLent {
        /// The seed the rule named.
        asked: BlockHash,
        /// The seed the job borrowed a cache for; `None` outside a job.
        lent: Option<BlockHash>,
    },
    /// The caller's stop flag ended a hash's permit wait. A stop, not a
    /// fault: nothing was judged.
    Stopped,
}

impl core::fmt::Display for SubstrateFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClockBeforeEpoch => f.write_str(
                "the system clock reads before the Unix epoch; no local time for the FTL rule",
            ),
            Self::SeedNotLent {
                asked,
                lent: Some(lent),
            } => write!(
                f,
                "a hash was asked under seed {asked:?} inside a job that borrowed the cache \
                 for seed {lent:?}; a job hashes under its own seed only"
            ),
            Self::SeedNotLent { asked, lent: None } => write!(
                f,
                "a hash was asked under seed {asked:?} where no cache was lent: every block \
                 there was to be answered from its recorded hash"
            ),
            Self::Stopped => f.write_str("the node is stopping; the hash did not run"),
        }
    }
}

impl core::error::Error for SubstrateFault {}

/// A substrate that answers [`Substrate::longhash`] from the proof-of-work
/// hashes this node already recorded, and asks `inner` for anything else
/// (`DRS_E5_POOL_ALT_PRUNE.md`, 2026-10-15 ruling 3). The switch forms the
/// blocks it re-judges through one — every demoted block and every
/// promoted one was hashed when this node first judged it — and ordinary
/// arrivals use the plain substrate.
///
/// Keyed by **(block identity, seed)**, never by identity alone: a seed
/// claim that differs from the one the hash was recorded under always
/// recomputes, so a wrong claim meets RandomX and then CEN-D3, exactly as
/// it would without the record. The identity is read off the PoW preimage
/// (`shekyl_wire::identity_of_pow_blob`), so nothing beside the blob the
/// rule hands over is trusted. The trait's contract already permits it:
/// "the implementor may cache by it".
///
/// What the record is trusted for: it was written by this node, after D2
/// computed it and D1 accepted it, under the store-integrity belts the
/// recorded cumulative difficulty sits under; no peer can reach it, and a
/// corrupted value can only touch a block this node already accepted once.
pub struct Recalled<'a, P: ?Sized> {
    inner: &'a P,
    recorded: std::collections::HashMap<(BlockHash, BlockHash), PowHash>,
}

impl<'a, P: ?Sized> Recalled<'a, P> {
    /// `inner`, answering from `recorded` — `(identity, seed, pow)` triples
    /// the store holds — where the key matches.
    pub fn new(
        inner: &'a P,
        recorded: impl IntoIterator<Item = (BlockHash, BlockHash, PowHash)>,
    ) -> Self {
        Self {
            inner,
            recorded: recorded
                .into_iter()
                .map(|(identity, seed, pow)| ((identity, seed), pow))
                .collect(),
        }
    }
}

impl<P: Substrate + ?Sized> Substrate for Recalled<'_, P> {
    type Fault = P::Fault;

    fn local_clock(&self) -> Result<Timestamp, P::Fault> {
        self.inner.local_clock()
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, P::Fault> {
        let identity = shekyl_wire::identity_of_pow_blob(pow_blob);
        match self.recorded.get(&(identity, *seed)) {
            Some(pow) => Ok(*pow),
            None => self.inner.longhash(pow_blob, seed),
        }
    }
}

#[cfg(all(test, feature = "pipeline"))]
#[path = "substrate_tests.rs"]
mod substrate_tests;
