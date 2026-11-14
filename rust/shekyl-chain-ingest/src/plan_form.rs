// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Step 1 of a switch (`DRS_E5_POOL_ALT_PRUNE.md` §2.3): `form` every block
//! a [`SwitchPlan`] names, off the actor, before [`Reorganize`] judges them
//! on it.
//!
//! One implementation for the two callers: the ingest service, whose router
//! carries out a switch an arrival made due, and the scenario driver, which
//! carries out the switches its tests script. The demoted blocks are formed
//! unless the verdict is the checkpoint's (K7 discards them), with no
//! reference claims: the cheap tier never compares one, and the chain
//! verified their proofs when it connected them. The promoted blocks claim
//! off the plan's header chain ([`SwitchPlan::references_for`]).
//!
//! Through [`Recalled`]: every block a plan names was hashed when this node
//! first judged it, and the plan carries that record, so a switch calls
//! RandomX only where a seed claim differs from the recorded one (ruling 3,
//! 2026-10-15).
//!
//! # One cache per run of the same seed
//!
//! The plan's blocks, in its order, are split into contiguous runs that
//! claim the same seed (`RANDOMX_CACHE_ACTOR.md` §5.3). A run with a block
//! whose claimed seed is not the one its hash was recorded under is one
//! [`Pow::lend`] job on that seed, at the chain's class: a recorded hash
//! takes no permit, and a miss takes one for its hash. A run whose every
//! block was recorded under the seed it claims asks for no job and no
//! cache ([`Pow::unlent`]): RandomX reached there is a fault, never a
//! build. A switch whose blocks all carry their recorded hashes therefore
//! builds nothing.
//!
//! [`Reorganize`]: crate::connector::Reorganize

use std::sync::atomic::AtomicBool;

use shekyl_chain_rules::{
    form, Candidate, FormAttempt, FormClaims, InvalidBlock, ReferenceClaims, StructurallyValid,
    Substrate,
};
use shekyl_hasher::Class;
use shekyl_types::BlockHash;

use crate::connector::{PlannedBlock, SwitchPlan};
use crate::pow::{LendJob, Pow};
use crate::schedule::ChainRules;
use crate::substrate::Recalled;

/// The blocks a plan named, formed, in its order.
#[derive(Debug)]
pub struct FormedPlan {
    /// The demoted blocks, ascending.
    pub demoted: Vec<StructurallyValid>,
    /// The alt entries, ascending.
    pub promoted: Vec<StructurallyValid>,
}

/// The first block `form` refused, in the plan's demoted-then-promoted
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanRefusal {
    /// Whether the block is one this node connected (a demotion) rather
    /// than an alt entry. A demoted block formed without claims refusing is
    /// a recorded block that fails its own stateless rules: the caller's
    /// invariant, never a verdict on the alternative chain.
    pub demoted: bool,
    /// The block's identity.
    pub hash: BlockHash,
    /// The verdict.
    pub refused: InvalidBlock,
}

/// Why forming stopped.
#[derive(Debug)]
pub enum PlanStop<F> {
    /// A block was refused (the first, in plan order).
    Refused(PlanRefusal),
    /// The substrate could not compute.
    Substrate(F),
    /// The caller's stop flag ended the forming: before a job was granted,
    /// or inside a hash's permit wait. Nothing was judged.
    Stopped,
}

/// One block of the plan's work: what is formed, where, and against which
/// reference claims.
type Work = (Candidate, PlannedBlock, ReferenceClaims);

/// Whether `at`'s hash was recorded under the seed it claims: the record
/// answers its longhash and RandomX is not reached.
fn recorded_under_claim(at: &PlannedBlock) -> bool {
    at.recorded.seed() == at.seed
}

/// `work`, split into contiguous runs that claim the same seed, each with
/// the index of its first block in the whole order.
fn seed_runs(work: Vec<Work>) -> Vec<(usize, BlockHash, Vec<Work>)> {
    let mut runs: Vec<(usize, BlockHash, Vec<Work>)> = Vec::new();
    for (index, item) in work.into_iter().enumerate() {
        match runs.last_mut() {
            Some((_, seed, run)) if *seed == item.1.seed => run.push(item),
            _ => runs.push((index, item.1.seed, vec![item])),
        }
    }
    runs
}

/// Form `plan`'s blocks through `pow`, each run of one seed across at most
/// [`Pow::permits`] threads (module docs). The first refusal in plan order
/// is the result; every thread is joined. Blocking.
///
/// # Errors
///
/// [`PlanStop`].
pub fn form_plan<P: Pow>(
    plan: &SwitchPlan,
    rules: ChainRules,
    pow: &P,
    stop: &AtomicBool,
) -> Result<FormedPlan, PlanStop<P::Fault>> {
    let mut work: Vec<Work> = plan
        .demoted
        .iter()
        .map(|d| (d.candidate.clone(), d.at.clone(), ReferenceClaims::EMPTY))
        .collect();
    let demoted_len = work.len();
    work.extend(plan.promoted.iter().map(|p| {
        let candidate = Candidate::new(p.block.clone(), p.transactions.clone())
            .with_bundle_references(p.references.clone())
            .with_bundle_bodies(p.bundle_bodies.clone());
        let references = plan.references_for(&p.at, &candidate);
        (candidate, p.at.clone(), references)
    }));
    let threads = pow.permits().max(1);
    let mut formed = Vec::with_capacity(work.len());
    // The runs are formed in plan order and the first stop ends the plan,
    // so a refusal in an earlier run is the first in plan order.
    for (start, seed, run) in seed_runs(work) {
        let recorded: Vec<_> = run
            .iter()
            .map(|(_, at, _)| (at.hash, at.recorded.seed(), at.recorded.pow()))
            .collect();
        let all_recorded = run.iter().all(|(_, at, _)| recorded_under_claim(at));
        let form_run = |job: &LendJob<'_, P::Fault>| {
            let recalled = Recalled::new(job, recorded);
            form_all(run, start, rules, &recalled, threads)
        };
        let blocks = if all_recorded {
            pow.unlent(form_run)
        } else {
            let Some(blocks) = pow.lend(Class::Chain, seed, stop, form_run) else {
                return Err(PlanStop::Stopped);
            };
            blocks
        };
        match blocks {
            Ok(blocks) => formed.extend(blocks),
            Err(Stop::Refused {
                index,
                hash,
                refused,
            }) => {
                return Err(PlanStop::Refused(PlanRefusal {
                    demoted: index < demoted_len,
                    hash,
                    refused,
                }))
            }
            Err(Stop::Substrate(fault)) if P::stopped(&fault) => return Err(PlanStop::Stopped),
            Err(Stop::Substrate(fault)) => return Err(PlanStop::Substrate(fault)),
        }
    }
    let promoted = formed.split_off(demoted_len);
    Ok(FormedPlan {
        demoted: formed,
        promoted,
    })
}

/// Why one chunk stopped, with the block's place in the whole order.
enum Stop<F> {
    Refused {
        index: usize,
        hash: BlockHash,
        refused: InvalidBlock,
    },
    Substrate(F),
}

impl<F> Stop<F> {
    /// The place a stop sorts by: a refusal by its index; a fault before
    /// any refusal, since it is the run's, not a block's.
    const fn rank(&self) -> usize {
        match self {
            Self::Refused { index, .. } => *index,
            Self::Substrate(_) => 0,
        }
    }
}

/// `form` every item of one seed run, in order, across `threads` contiguous
/// chunks. `first` is the run's first index in the whole plan.
fn form_all<S>(
    work: Vec<Work>,
    first: usize,
    rules: ChainRules,
    substrate: &S,
    threads: usize,
) -> Result<Vec<StructurallyValid>, Stop<S::Fault>>
where
    S: Substrate + Sync + ?Sized,
    S::Fault: Send,
{
    let chunk = work.len().div_ceil(threads).max(1);
    let mut chunks = Vec::new();
    let mut rest = work;
    let mut start = first;
    while !rest.is_empty() {
        let n = chunk.min(rest.len());
        let tail = rest.split_off(n);
        chunks.push((start, rest));
        start += n;
        rest = tail;
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|(start, chunk)| {
                scope.spawn(move || {
                    let mut formed = Vec::with_capacity(chunk.len());
                    for (local, (candidate, at, references)) in chunk.into_iter().enumerate() {
                        match form(
                            candidate,
                            &FormClaims {
                                rule_set: &rules.in_force(at.height),
                                seed: at.seed,
                                target: at.target,
                                references: &references,
                                network: rules.trust().network_id(),
                            },
                            substrate,
                            FormAttempt::FIRST,
                        ) {
                            Ok(Ok(valid)) => formed.push(valid),
                            Ok(Err(refused)) => {
                                return Err(Stop::Refused {
                                    index: start + local,
                                    hash: at.hash,
                                    refused,
                                })
                            }
                            Err(fault) => return Err(Stop::Substrate(fault)),
                        }
                    }
                    Ok(formed)
                })
            })
            .collect();
        let mut formed = Vec::new();
        let mut stop: Option<Stop<S::Fault>> = None;
        for handle in handles {
            match handle.join().expect("a forming thread does not panic") {
                Ok(blocks) => formed.extend(blocks),
                Err(found) => {
                    stop = Some(match stop {
                        Some(kept) if kept.rank() <= found.rank() => kept,
                        _ => found,
                    });
                }
            }
        }
        stop.map_or(Ok(formed), Err)
    })
}
