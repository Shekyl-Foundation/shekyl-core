// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor (CS-3 §4.4): the model's [`Command::Prove`] jobs, run under
//! the daemon's hasher budget, answered as one [`Event::Proven`].
//!
//! Each item takes one permit of its class and gives it back before the
//! next, in order, and the job stops at the first refusal or fault, exactly
//! as `form_header` returns it. The cache an item hashes under is its plan's
//! (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2 step 3, B2):
//!
//! - [`CachePlan::Main`]: the ingest window's two slots, looked up and
//!   never derived. A miss is [`Proved::NotHeld`]; the model drops the run.
//! - [`CachePlan::Branch`]: the executor's one branch cache, derived outside
//!   the slots under the item's permit, replaced when the seed changes, and
//!   never pinned. One derivation at a time.
//! - [`CachePlan::Evidence`]: a cache derived for this job and dropped when
//!   it ends. It never evicts either ingest slot.
//!
//! [`Command::Prove`]: crate::Command::Prove
//! [`Event::Proven`]: crate::Event::Proven

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::{ProductionSubstrate, SubstrateFault};
use shekyl_chain_rules::{form_header, CenRow, InvalidBlock, Locus, Substrate};
use shekyl_hash_budget::{Budget, Class};
use shekyl_pow_randomx::{PreparedCache, Seedhash};
use shekyl_types::{BlockHash, PowHash, Timestamp};
use shekyl_wire::PowBlob;

use crate::model::{CachePlan, HashClass, ProveItem, Proved};

/// The budget class a model [`HashClass`] runs under: one to one.
#[must_use]
pub const fn budget_class(class: HashClass) -> Class {
    match class {
        HashClass::HeaderPow => Class::HeaderPow,
        HashClass::Unsolicited => Class::Unsolicited,
        HashClass::Evidence => Class::Evidence,
    }
}

/// The prove jobs' runner. Cheap to share: one per sync owner.
pub struct Executor {
    budget: Budget,
    substrate: ProductionSubstrate,
    /// The one branch cache: built outside the store's slots, replaced when
    /// a job names another seed. The lock serialises branch derivations.
    branch: Mutex<Option<Arc<PreparedCache>>>,
    stop: Arc<AtomicBool>,
}

impl Executor {
    /// An executor over `substrate` (its cache store is the ingest
    /// service's, so a main seed is the window ingest pinned), taking its
    /// permits from `budget` and giving up a wait once `stop` is set.
    #[must_use]
    pub fn new(budget: Budget, substrate: ProductionSubstrate, stop: Arc<AtomicBool>) -> Self {
        Self {
            budget,
            substrate,
            branch: Mutex::new(None),
            stop,
        }
    }

    /// Run one job. Blocking: a permit wait and RandomX run on the calling
    /// thread, so call it from a blocking task.
    ///
    /// The results are in item order. They end early at the first
    /// [`Proved::Refused`] or [`Proved::NotHeld`], or when the budget is
    /// stopped before the next permit.
    #[must_use]
    pub fn run(&self, class: HashClass, cache: CachePlan, items: &[ProveItem]) -> Vec<Proved> {
        let class = budget_class(class);
        let mut results = Vec::with_capacity(items.len());
        let mut evidence: Option<Arc<PreparedCache>> = None;
        for item in items {
            let Some(permit) = self.budget.acquire_unless(class, &self.stop) else {
                break;
            };
            let held = match cache {
                CachePlan::Main(_) => None,
                CachePlan::Branch(seed) => Some(self.branch_cache(seed)),
                CachePlan::Evidence(seed) => Some(Arc::clone(
                    evidence.get_or_insert_with(|| self.derive(seed)),
                )),
            };
            let Ok(pow) = PowBlob::read(&item.pow) else {
                // The model writes the preimage from a parsed one. One that
                // does not read back is not a header.
                results.push(Proved::Refused(InvalidBlock::new(CenRow::A6, Locus::Block)));
                break;
            };
            let substrate = HeldSubstrate {
                base: &self.substrate,
                held: held.as_ref(),
            };
            let verdict = form_header(
                &pow,
                &item.rule_set,
                &substrate,
                item.seed,
                item.target,
                item.attempt,
            );
            drop(permit);
            match verdict {
                Ok(Ok(formed)) => results.push(Proved::Formed(Box::new(formed))),
                Ok(Err(refused)) => {
                    results.push(Proved::Refused(refused));
                    break;
                }
                Err(SubstrateFault::CacheAbsent) => {
                    if held.is_some() {
                        tracing::error!(
                            seed = ?item.seed,
                            "a prepared cache did not answer its own seed: a defect"
                        );
                    }
                    results.push(Proved::NotHeld);
                    break;
                }
                Err(fault @ SubstrateFault::ClockBeforeEpoch) => {
                    tracing::error!(%fault, "the proof could not be judged");
                    break;
                }
            }
        }
        results
    }

    /// CEN-C1's wall clock: the substrate's, which the owner reads once
    /// per event for [`crate::Sync::set_wall`].
    ///
    /// # Errors
    ///
    /// The substrate's clock read before the epoch.
    pub fn wall(&self) -> Result<Timestamp, SubstrateFault> {
        self.substrate.local_clock()
    }

    /// The branch cache for `seed`: the one held when it is that seed's,
    /// otherwise a new derivation that replaces it.
    fn branch_cache(&self, seed: BlockHash) -> Arc<PreparedCache> {
        let mut branch = self.branch.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cache) = branch.as_ref() {
            if cache.seedhash().as_bytes() == seed.as_bytes() {
                return Arc::clone(cache);
            }
        }
        let cache = self.derive(seed);
        *branch = Some(Arc::clone(&cache));
        cache
    }

    /// One derivation outside the store's slots, recorded as a derive.
    fn derive(&self, seed: BlockHash) -> Arc<PreparedCache> {
        let seedhash = Seedhash::from_bytes(*seed.as_bytes());
        Arc::new(
            self.substrate
                .metrics()
                .timed_derive(|| PreparedCache::derive(seedhash)),
        )
    }

    /// The seed the branch cache holds now, if any.
    #[cfg(test)]
    pub(crate) fn branch_seed(&self) -> Option<BlockHash> {
        self.branch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|cache| BlockHash::from_bytes(*cache.seedhash().as_bytes()))
    }
}

/// The production substrate, hashing under a held cache when the plan
/// names one, and looking the slots up when it does not.
struct HeldSubstrate<'a> {
    base: &'a ProductionSubstrate,
    held: Option<&'a Arc<PreparedCache>>,
}

impl Substrate for HeldSubstrate<'_> {
    type Fault = SubstrateFault;
    type Held = ();

    fn local_clock(&self) -> Result<Timestamp, SubstrateFault> {
        self.base.local_clock()
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, SubstrateFault> {
        match self.held {
            Some(cache) => self
                .base
                .longhash_held(pow_blob, seed, &Some(Arc::clone(cache))),
            None => self.base.longhash(pow_blob, seed),
        }
    }

    fn cache_absent(&self, fault: &SubstrateFault) -> bool {
        matches!(fault, SubstrateFault::CacheAbsent)
    }
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
