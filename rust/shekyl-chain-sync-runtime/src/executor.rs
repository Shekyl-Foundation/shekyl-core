// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor (CS-3 §4.4): the model's [`Command::Prove`] jobs, run as
//! jobs on the node's one hasher, answered as one [`Event::Proven`].
//!
//! A prove job names one seed, and the executor borrows that seed's cache
//! for the job ([`Pow::lend`], `RANDOMX_CACHE_ACTOR.md` §5.3): the hasher
//! builds it when it is not warm, inside its cap, and frees it when
//! nothing needs it. The executor holds no cache and no budget. Which seed
//! a header may be proven under is the model's rule
//! (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2 step 3); what keeps its cache
//! resident between jobs is the ranked list, which the owner feeds with
//! the model's frontier.
//!
//! Each item takes one permit of the job's class for its hash, and a job's
//! items are spread across as many lanes as the hasher has permits
//! ([`prove`]). The answer is in item order and stops at the first refusal
//! or fault, exactly as `form_header` returns it.
//!
//! [`Command::Prove`]: shekyl_chain_sync::Command::Prove
//! [`Event::Proven`]: shekyl_chain_sync::Event::Proven

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_ingest::pow::{LendJob, Pow};
use shekyl_chain_ingest::{ProductionPow, SubstrateFault};
use shekyl_chain_rules::{form_header, CenRow, InvalidBlock, Locus};
use shekyl_hasher::Class;
use shekyl_types::{BlockHash, Timestamp};
use shekyl_wire::PowBlob;

use shekyl_chain_sync::{HashClass, ProveItem, Proved};

/// The hasher class a model [`HashClass`] runs under: one to one.
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
    pow: ProductionPow,
    /// Set by [`Self::stop`]; a job's wait for its cache, and an item's
    /// wait for its permit, give up once it is.
    stop: AtomicBool,
}

impl Executor {
    /// An executor over `pow`, the boundary over the node's one hasher,
    /// which the ingest forms under too.
    #[must_use]
    pub const fn new(pow: ProductionPow) -> Self {
        Self {
            pow,
            stop: AtomicBool::new(false),
        }
    }

    /// Stop: every wait gives up, and no item is proven after it. The
    /// hasher is woken after the flag is set, so a job already parked
    /// waiting for a cache or a permit sees the flag now, not when one
    /// frees.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.pow.wake();
    }

    /// The measurement sink the boundary hashes into, which the owner
    /// also times its own phases into (CS-5, the per-block profile).
    #[must_use]
    pub const fn metrics(&self) -> &Arc<shekyl_chain_ingest::Metrics> {
        self.pow.metrics()
    }

    /// The per-block profile as of now: the sink's counters and the
    /// hasher's derives.
    #[must_use]
    pub fn artifact(&self) -> shekyl_chain_ingest::MetricsArtifact {
        self.pow.artifact()
    }

    /// The hasher's permits: the most items of one job hashed at once, and
    /// the owner row's blocking-thread cap.
    #[must_use]
    pub fn permits(&self) -> usize {
        self.pow.permits()
    }

    /// CEN-C1's wall clock: the boundary's, which the owner reads once per
    /// event for [`shekyl_chain_sync::Sync::set_wall`].
    ///
    /// # Errors
    ///
    /// The clock read before the epoch.
    pub fn wall(&self) -> Result<Timestamp, SubstrateFault> {
        self.pow.clock()
    }

    /// One `Prove` job, as one job on `seed` (module docs). Blocking.
    ///
    /// The lanes are scoped OS threads, not the runtime's: a loan cannot
    /// leave the job that borrowed it, so it cannot go to a blocking task.
    /// Each lane takes the next item not yet taken, and stops taking once
    /// an earlier item ended the job. A lane already waiting for its
    /// permit when that happens still hashes its item; its answer is
    /// dropped.
    fn prove_blocking(&self, class: Class, seed: BlockHash, items: &[ProveItem]) -> Vec<Proved> {
        let lanes = self.permits().max(1).min(items.len());
        // The lowest index that ended the job; items above it are not
        // taken.
        let ended = AtomicUsize::new(usize::MAX);
        let next = AtomicUsize::new(0);
        let slots: Vec<Mutex<Option<Proved>>> = items.iter().map(|_| Mutex::new(None)).collect();
        let granted = self.pow.lend(class, seed, &self.stop, |job| {
            std::thread::scope(|scope| {
                for _ in 0..lanes {
                    scope.spawn(|| loop {
                        let index = next.fetch_add(1, Ordering::AcqRel);
                        if index >= items.len() || index > ended.load(Ordering::Acquire) {
                            break;
                        }
                        let proved = prove_one(job, &items[index]);
                        if !matches!(proved, Some(Proved::Formed(_))) {
                            ended.fetch_min(index, Ordering::AcqRel);
                        }
                        *slots[index].lock().unwrap_or_else(PoisonError::into_inner) = proved;
                    });
                }
            });
        });
        if granted.is_none() {
            // The stop came before the job was granted: nothing was proven.
            return Vec::new();
        }
        let mut results = Vec::with_capacity(slots.len());
        for slot in slots {
            let Some(proved) = slot.into_inner().unwrap_or_else(PoisonError::into_inner) else {
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
}

/// Prove one item inside the job. `None` when a stop reached the hash, or
/// the item could not be judged: the clock, or a seed the job did not
/// borrow, which is a defect in the model's batching and never a verdict.
fn prove_one(job: &LendJob<'_, SubstrateFault>, item: &ProveItem) -> Option<Proved> {
    let Ok(pow) = PowBlob::read(&item.pow) else {
        // The model writes the preimage from a parsed one. One that does
        // not read back is not a header.
        return Some(Proved::Refused(InvalidBlock::new(CenRow::A6, Locus::Block)));
    };
    let verdict = form_header(
        &pow,
        &item.rule_set,
        job,
        item.seed,
        item.target,
        item.attempt,
    );
    match verdict {
        Ok(Ok(formed)) => Some(Proved::Formed(Box::new(formed))),
        Ok(Err(refused)) => Some(Proved::Refused(refused)),
        // A stop, not a fault: nothing was judged, and nothing is logged
        // as an error.
        Err(SubstrateFault::Stopped) => None,
        Err(fault @ (SubstrateFault::SeedNotLent { .. } | SubstrateFault::ClockBeforeEpoch)) => {
            tracing::error!(%fault, "the proof could not be judged");
            None
        }
    }
}

/// Run one `Prove` job and answer it in item order.
///
/// The job borrows `seed`'s cache once, and its items are spread across
/// the hasher's permits: as many are hashed at once as there are permits,
/// each under one permit of the job's class, so the hasher's budget, not
/// this function, decides how much RandomX runs. The answer stops at the
/// first item that is not formed, exactly as `form_header` returns it; an
/// item after it is not taken once that is known. A stop ends the answer
/// at the first item it did not prove.
///
/// The job is one blocking task of the owner's row; its lanes are scoped
/// threads of that task.
pub async fn prove(
    executor: Arc<Executor>,
    class: HashClass,
    seed: BlockHash,
    items: Vec<ProveItem>,
) -> Vec<Proved> {
    let class = budget_class(class);
    match tokio::task::spawn_blocking(move || executor.prove_blocking(class, seed, &items)).await {
        Ok(results) => results,
        Err(join) => {
            tracing::error!(%join, "a proof job ended without an answer");
            Vec::new()
        }
    }
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
