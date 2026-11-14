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
//! ([`prove`]). The answer is in item order and stops at the first
//! refusal, exactly as `form_header` returns it.
//!
//! An item that cannot be judged is not an answer. A hash asked under a
//! seed the job did not borrow is a defect in the model's batching, and a
//! clock before the epoch is the host's: neither is a verdict on a header,
//! and neither heals when the model plans the item again. The job returns
//! the [`ProveFault`], and the owner ends on it
//! ([`EndCause::ProofUnjudged`](crate::owner::EndCause::ProofUnjudged)).
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

/// Why a prove job could not judge an item: never a verdict on the header,
/// and never a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveFault {
    /// The item named `asked` inside a job that borrowed `lent`'s cache:
    /// the model put a header in a job under another seed.
    SeedNotLent {
        /// The seed the item's rule named.
        asked: BlockHash,
        /// The seed the job borrowed a cache for.
        lent: BlockHash,
    },
    /// The system clock reads before the Unix epoch, so the FTL rule
    /// (CEN-C1) has no local time.
    ClockBeforeEpoch,
}

impl ProveFault {
    /// The prose of this fault, without its seeds.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::SeedNotLent { .. } => {
                "a header proof was asked under a seed its job did not borrow"
            }
            Self::ClockBeforeEpoch => "a header proof found the system clock before the Unix epoch",
        }
    }
}

impl std::fmt::Display for ProveFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeedNotLent { asked, lent } => write!(
                formatter,
                "{}: the item named {asked:?}, the job borrowed {lent:?}",
                self.text()
            ),
            Self::ClockBeforeEpoch => formatter.write_str(self.text()),
        }
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
    ///
    /// # Errors
    ///
    /// The fault of the lowest item that could not be judged, when no item
    /// before it ended the answer.
    fn prove_blocking(
        &self,
        class: Class,
        seed: BlockHash,
        items: &[ProveItem],
    ) -> Result<Vec<Proved>, ProveFault> {
        let lanes = self.permits().max(1).min(items.len());
        // The lowest index that ended the job; items above it are not
        // taken.
        let ended = AtomicUsize::new(usize::MAX);
        let next = AtomicUsize::new(0);
        let slots: Vec<Mutex<Option<Result<Proved, ProveFault>>>> =
            items.iter().map(|_| Mutex::new(None)).collect();
        let granted = self.pow.lend(class, seed, &self.stop, |job| {
            std::thread::scope(|scope| {
                for _ in 0..lanes {
                    scope.spawn(|| loop {
                        let index = next.fetch_add(1, Ordering::AcqRel);
                        if index >= items.len() || index > ended.load(Ordering::Acquire) {
                            break;
                        }
                        let proved = prove_one(job, seed, &items[index]);
                        if !matches!(proved, Some(Ok(Proved::Formed(_)))) {
                            ended.fetch_min(index, Ordering::AcqRel);
                        }
                        *slots[index].lock().unwrap_or_else(PoisonError::into_inner) = proved;
                    });
                }
            });
        });
        if granted.is_none() {
            // The stop came before the job was granted: nothing was proven.
            return Ok(Vec::new());
        }
        let mut results = Vec::with_capacity(slots.len());
        for slot in slots {
            let Some(proved) = slot.into_inner().unwrap_or_else(PoisonError::into_inner) else {
                break;
            };
            let proved = proved?;
            let last = !matches!(proved, Proved::Formed(_));
            results.push(proved);
            if last {
                break;
            }
        }
        Ok(results)
    }
}

/// Prove one item inside the job on `lent`. `None` when a stop reached
/// the hash: nothing was judged, and nothing is a fault. An item that
/// could not be judged is its [`ProveFault`].
fn prove_one(
    job: &LendJob<'_, SubstrateFault>,
    lent: BlockHash,
    item: &ProveItem,
) -> Option<Result<Proved, ProveFault>> {
    let Ok(pow) = PowBlob::read(&item.pow) else {
        // The model writes the preimage from a parsed one. One that does
        // not read back is not a header.
        return Some(Ok(Proved::Refused(InvalidBlock::new(
            CenRow::A6,
            Locus::Block,
        ))));
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
        Ok(Ok(formed)) => Some(Ok(Proved::Formed(Box::new(formed)))),
        Ok(Err(refused)) => Some(Ok(Proved::Refused(refused))),
        // A stop, not a fault: nothing was judged.
        Err(SubstrateFault::Stopped) => None,
        // The job's substrate names the seed it was lent; a job always
        // has one, so `lent` is the job's own.
        Err(SubstrateFault::SeedNotLent { asked, .. }) => {
            Some(Err(ProveFault::SeedNotLent { asked, lent }))
        }
        Err(SubstrateFault::ClockBeforeEpoch) => Some(Err(ProveFault::ClockBeforeEpoch)),
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
///
/// # Errors
///
/// The [`ProveFault`] of the first item that could not be judged, when
/// every item before it formed. No answer is cut short for it: the owner
/// ends (module docs).
pub async fn prove(
    executor: Arc<Executor>,
    class: HashClass,
    seed: BlockHash,
    items: Vec<ProveItem>,
) -> Result<Vec<Proved>, ProveFault> {
    let class = budget_class(class);
    match tokio::task::spawn_blocking(move || executor.prove_blocking(class, seed, &items)).await {
        Ok(answer) => answer,
        Err(join) => {
            tracing::error!(%join, "a proof job ended without an answer");
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
