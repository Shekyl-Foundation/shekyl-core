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
//! [`Reorganize`]: crate::connector::Reorganize

use shekyl_chain_rules::{
    form, Candidate, FormAttempt, InvalidBlock, ReferenceClaims, StructurallyValid, Substrate,
};
use shekyl_difficulty::ForkChoiceVerdict;
use shekyl_types::BlockHash;

use crate::connector::{PlannedBlock, SwitchPlan};
use crate::schedule::ChainRules;
use crate::substrate::Recalled;

/// The blocks a plan named, formed, in its order.
#[derive(Debug)]
pub struct FormedPlan {
    /// The demoted blocks, ascending; empty for `ForcedSwitch`.
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
}

/// Form `plan`'s blocks under `substrate`, across at most `threads` threads
/// (module docs). The first refusal in plan order is the result; every
/// thread is joined. `permit` is taken for the life of each block's `form`:
/// the hasher budget's permit for the service, nothing for the scenario.
///
/// # Errors
///
/// [`PlanStop`].
pub fn form_plan<S, G, R>(
    plan: &SwitchPlan,
    rules: ChainRules,
    substrate: &S,
    threads: usize,
    permit: &G,
) -> Result<FormedPlan, PlanStop<S::Fault>>
where
    S: Substrate + Sync,
    S::Fault: Send,
    G: Fn() -> R + Sync,
    R: Send,
{
    let mut work: Vec<(Candidate, PlannedBlock, ReferenceClaims)> = Vec::new();
    if plan.verdict != ForkChoiceVerdict::ForcedSwitch {
        work.extend(
            plan.demoted
                .iter()
                .map(|d| (d.candidate.clone(), d.at.clone(), ReferenceClaims::EMPTY)),
        );
    }
    let demoted_len = work.len();
    work.extend(plan.promoted.iter().map(|p| {
        let candidate = Candidate::new(p.block.clone(), p.transactions.clone())
            .with_attestation_witness(p.witness.clone());
        let references = plan.references_for(&p.at, &candidate);
        (candidate, p.at.clone(), references)
    }));
    let recalled = Recalled::new(
        substrate,
        work.iter()
            .map(|(_, at, _)| (at.hash, at.recorded.seed(), at.recorded.pow())),
    );
    let mut formed =
        form_all(work, rules, &recalled, threads.max(1), permit).map_err(|stop| match stop {
            Stop::Refused {
                index,
                hash,
                refused,
            } => PlanStop::Refused(PlanRefusal {
                demoted: index < demoted_len,
                hash,
                refused,
            }),
            Stop::Substrate(fault) => PlanStop::Substrate(fault),
        })?;
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

/// `form` every item, in order, across `threads` contiguous chunks.
fn form_all<S, G, R>(
    work: Vec<(Candidate, PlannedBlock, ReferenceClaims)>,
    rules: ChainRules,
    substrate: &S,
    threads: usize,
    permit: &G,
) -> Result<Vec<StructurallyValid>, Stop<S::Fault>>
where
    S: Substrate + Sync,
    S::Fault: Send,
    G: Fn() -> R + Sync,
    R: Send,
{
    let chunk = work.len().div_ceil(threads).max(1);
    let mut chunks = Vec::new();
    let mut rest = work;
    let mut start = 0;
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
                        let _permit = permit();
                        match form(
                            candidate,
                            &rules.in_force(at.height),
                            substrate,
                            at.seed,
                            at.target,
                            &references,
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
