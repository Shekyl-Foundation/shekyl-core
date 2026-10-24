// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor (CS-3 §4.4): the model's [`Command::Prove`] jobs, run under
//! the daemon's hasher budget, answered as one [`Event::Proven`].
//!
//! Each item takes one permit of its class, and a job's items are spread
//! across the budget's permits ([`prove`]). The answer is in item order and
//! stops at the first refusal or fault, exactly as `form_header` returns it.
//! The cache an item hashes under is its plan's (`P2P_3_CHAIN_SYNC_BRIEF.md`
//! CS-Q2 step 3, B2):
//!
//! - [`CachePlan::Main`]: the ingest window's two slots, looked up and
//!   never derived. A miss is [`Proved::NotHeld`]; the model drops the run.
//! - [`CachePlan::Branch`]: the executor's one branch cache, derived outside
//!   the slots under one permit of the job's class, replaced when the seed
//!   changes, and never pinned. One derivation at a time.
//! - [`CachePlan::Evidence`]: a cache derived for this job and dropped when
//!   it ends. It never evicts either ingest slot.
//!
//! [`Command::Prove`]: shekyl_chain_sync::Command::Prove
//! [`Event::Proven`]: shekyl_chain_sync::Event::Proven

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::{ProductionSubstrate, SubstrateFault};
use shekyl_chain_rules::{form_header, CenRow, InvalidBlock, Locus, Substrate};
use shekyl_hash_budget::{Budget, Class};
use shekyl_pow_randomx::{PreparedCache, Seedhash};
use shekyl_types::{BlockHash, PowHash, Timestamp};
use shekyl_wire::PowBlob;

use shekyl_chain_sync::{CachePlan, HashClass, ProveItem, Proved};

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
    /// Set by [`Self::stop`]; a permit wait gives up once it is.
    stop: AtomicBool,
}

impl Executor {
    /// An executor over `substrate` (its cache store is the ingest
    /// service's, so a main seed is the window ingest pinned), taking its
    /// permits from `budget`.
    #[must_use]
    pub fn new(budget: Budget, substrate: ProductionSubstrate) -> Self {
        Self {
            budget,
            substrate,
            branch: Mutex::new(None),
            stop: AtomicBool::new(false),
        }
    }

    /// Stop: every permit wait gives up, and no item is proven after it.
    /// The budget is woken after the flag is set, so a job already parked
    /// on a full budget sees the flag now, not when a permit frees.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.budget.wake();
    }

    /// The budget's permits: the most items of one job hashed at once, and
    /// the owner row's blocking-thread cap.
    #[must_use]
    pub fn permits(&self) -> usize {
        self.budget.permits()
    }

    /// The cache a job's plan hashes under. `Lookup` is a main seed: the
    /// slots are looked up and nothing is held. `Held` is the executor's
    /// one branch cache, derived under one permit of the job's class when
    /// the seed is new, or an evidence cache derived for this job and
    /// dropped with it. `Stopped` when the budget stopped before a needed
    /// permit. Blocking.
    fn prepare(&self, class: Class, cache: CachePlan) -> Prepared {
        match cache {
            CachePlan::Main(_) => Prepared::Lookup,
            CachePlan::Branch(seed) => {
                if let Some(held) = self.branch_held(seed) {
                    return Prepared::Held(held);
                }
                let Some(_permit) = self.budget.acquire_unless(class, &self.stop) else {
                    return Prepared::Stopped;
                };
                Prepared::Held(self.branch_cache(seed))
            }
            CachePlan::Evidence(seed) => {
                let Some(_permit) = self.budget.acquire_unless(class, &self.stop) else {
                    return Prepared::Stopped;
                };
                Prepared::Held(self.derive(seed))
            }
        }
    }

    /// Prove one item under one permit of `class`. `None` when the budget
    /// stopped first, when `abandoned` says an earlier item already ended
    /// the job, or when the clock cannot be read. Blocking.
    fn prove_one(
        &self,
        class: Class,
        held: Option<&Arc<PreparedCache>>,
        item: &ProveItem,
        abandoned: impl Fn() -> bool,
    ) -> Option<Proved> {
        let permit = self.budget.acquire_unless(class, &self.stop)?;
        if abandoned() {
            return None;
        }
        let Ok(pow) = PowBlob::read(&item.pow) else {
            // The model writes the preimage from a parsed one. One that
            // does not read back is not a header.
            return Some(Proved::Refused(InvalidBlock::new(CenRow::A6, Locus::Block)));
        };
        let substrate = HeldSubstrate {
            base: &self.substrate,
            held,
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
            Ok(Ok(formed)) => Some(Proved::Formed(Box::new(formed))),
            Ok(Err(refused)) => Some(Proved::Refused(refused)),
            Err(SubstrateFault::CacheAbsent) => {
                if held.is_some() {
                    tracing::error!(
                        seed = ?item.seed,
                        "a prepared cache did not answer its own seed: a defect"
                    );
                }
                Some(Proved::NotHeld)
            }
            Err(fault @ SubstrateFault::ClockBeforeEpoch) => {
                tracing::error!(%fault, "the proof could not be judged");
                None
            }
        }
    }

    /// CEN-C1's wall clock: the substrate's, which the owner reads once
    /// per event for [`shekyl_chain_sync::Sync::set_wall`].
    ///
    /// # Errors
    ///
    /// The substrate's clock read before the epoch.
    pub fn wall(&self) -> Result<Timestamp, SubstrateFault> {
        self.substrate.local_clock()
    }

    /// The branch cache, when it is `seed`'s.
    fn branch_held(&self, seed: BlockHash) -> Option<Arc<PreparedCache>> {
        self.branch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|cache| cache.seedhash().as_bytes() == seed.as_bytes())
            .map(Arc::clone)
    }

    /// The branch cache for `seed`: the one held when it is that seed's,
    /// otherwise a new derivation that replaces it. The lock serialises
    /// the derivations.
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

/// Run one `Prove` job and answer it in item order.
///
/// The job's items are spread across the budget's permits: as many are
/// hashed at once as the budget has permits, each under one permit of its
/// class, so the budget, not this function, decides how much RandomX runs.
/// The answer stops at the first item that is not formed (a refusal, a
/// main seed not held), exactly as `form_header` returns it; an item after
/// it is not hashed once that is known. A budget that stops ends the
/// answer at the first item it did not prove.
pub async fn prove(
    executor: Arc<Executor>,
    class: HashClass,
    cache: CachePlan,
    items: Vec<ProveItem>,
) -> Vec<Proved> {
    let class = budget_class(class);
    let prepared = {
        let executor = Arc::clone(&executor);
        tokio::task::spawn_blocking(move || executor.prepare(class, cache)).await
    };
    let held = match prepared {
        Ok(Prepared::Held(held)) => Some(held),
        Ok(Prepared::Lookup) => None,
        Ok(Prepared::Stopped) | Err(_) => return Vec::new(),
    };
    let lanes = executor.permits().max(1);
    let items = Arc::new(items);
    // The lowest index that ended the job; items above it are not hashed.
    let ended = Arc::new(AtomicUsize::new(usize::MAX));
    let mut slots: Vec<Option<Proved>> = vec![None; items.len()];
    let mut running = tokio::task::JoinSet::new();
    let mut next = 0;
    loop {
        while running.len() < lanes && next < items.len() && next <= ended.load(Ordering::Acquire) {
            let index = next;
            next += 1;
            let executor = Arc::clone(&executor);
            let items = Arc::clone(&items);
            let held = held.clone();
            let ended = Arc::clone(&ended);
            running.spawn_blocking(move || {
                let abandoned = || index > ended.load(Ordering::Acquire);
                let proved = executor.prove_one(class, held.as_ref(), &items[index], abandoned);
                if !matches!(proved, Some(Proved::Formed(_))) {
                    ended.fetch_min(index, Ordering::AcqRel);
                }
                (index, proved)
            });
        }
        match running.join_next().await {
            Some(Ok((index, proved))) => slots[index] = proved,
            Some(Err(join)) => {
                tracing::error!(%join, "a proof task ended without an answer");
                ended.store(0, Ordering::Release);
            }
            None => break,
        }
    }
    let mut results = Vec::with_capacity(slots.len());
    for slot in slots {
        let Some(proved) = slot else {
            break;
        };
        let last = !matches!(proved, Proved::Formed(_));
        results.push(proved);
        if last {
            break;
        }
    }
    results
}

/// The cache [`Executor::prepare`] returns.
enum Prepared {
    /// The budget stopped before a permit the plan needed.
    Stopped,
    /// A main seed. The slots are looked up, and nothing is held.
    Lookup,
    /// A branch or evidence cache, held for the job.
    Held(Arc<PreparedCache>),
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
