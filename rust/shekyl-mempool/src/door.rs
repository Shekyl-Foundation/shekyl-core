// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool door: the validator's own judgement of one transaction, and
//! nothing else (DRS-E5 PR-b b2; `DRS_E5_POOL_ALT_PRUNE.md` §2.2).
//!
//! Three calls, in order:
//!
//! 1. [`judge_lone_stateless`] — the function `form` runs at every slot,
//!    at [`TxSlot::Lone`]: `tx_form` (CEN-M2: the full NIC set), the
//!    signatures, the proofs against the claim read off this chain
//!    ([`ReferenceClaims::for_transaction`]), and the range proof as a
//!    batch of one. Its answer is a [`StatelessPass`], and a pass the pool
//!    already holds for the transaction is the answer again while its rule
//!    set and its claim hold (CEN-M8; the review of #1102, S1): nothing is
//!    verified twice.
//! 2. [`tx_against`] at `Lone` over [`PoolView`] — the view-bound half
//!    `validate` runs per slot, with the pool's key images added (CEN-M6,
//!    CEN-M7); it compares the chain's `(height, root)` at the reference
//!    with the claim step 1 verified.
//! 3. [`policy_form`] — CEN-M3, M4 and M5 over the relay floor window at
//!    the connecting height.
//!
//! Step 1 is [`stateless`], which needs no pool: a caller holding a lock
//! runs it before taking the lock and hands its pass to [`judge`], which
//! re-reads the claim under the lock and runs step 1 again only if the
//! claim moved in between.
//!
//! The answer names the step that refused, and the first refusal is the
//! answer: the pool drops a refused transaction whichever step refused it.
//! The submit engine reads the step to classify its reply (a chain-bound
//! refusal may be a race with a block or a held spend, `rust_pool_shim`).
//!
//! Steps 2 and 3 read the view step 1's claim was read off, so the claim
//! and the chain it is compared with cannot disagree: a
//! [`Stale`](shekyl_chain_rules::Stale) here is a view that moved under its
//! reader, and comes back as the fault.

use shekyl_chain_rules::{
    judge_lone_stateless, policy_form, relay_floor_window, tx_against, AdmissionPolicy, AtHeight,
    ChainView, Fault, FormAttempt, InvalidBlock, PolicyCoverage, PolicyRefused, ReferenceClaims,
    RuleCoverage, RuleSet, StatelessPass, Tip, TxSlot,
};
use shekyl_wire::Transaction;

use crate::view::{KeyImages, PoolView};

/// What the door decided about one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Judged {
    /// Every row passed.
    Admitted {
        /// Step 1's pass: what the proof verified against (CEN-M8's
        /// anchor) and the consensus rows it recorded. Boxed: every enum
        /// that carries a judgement would otherwise carry its size.
        pass: Box<StatelessPass>,
        /// The consensus rows step 2 recorded.
        against: RuleCoverage,
        /// The policy rows step 3 recorded.
        policy: PolicyCoverage,
    },
    /// Refused on the transaction's bytes (step 1): no chain admits it.
    Stateless(InvalidBlock),
    /// Refused by the chain-bound half (step 2), against this chain.
    Chain(InvalidBlock),
    /// Admitted by the consensus rows and refused by the admission policy
    /// (step 3).
    Policy(PolicyRefused),
}

/// Step 1 for `tx` against `chain` under `rule_set`, at the height a block
/// carrying it would connect at: `prior` when it still holds, else the
/// judgement itself (module docs).
///
/// # Errors
///
/// The view's fault. None is a judgement about the transaction.
pub fn stateless<'id, V: ChainView<'id>>(
    tx: &Transaction,
    chain: &V,
    rule_set: &RuleSet,
    prior: Option<&StatelessPass>,
) -> Result<Result<StatelessPass, InvalidBlock>, Fault<V::Fault>> {
    let connecting = Tip::connecting_height(chain.tip().map_err(Fault::View)?.as_ref());
    let claims = ReferenceClaims::for_transaction(chain, connecting, tx).map_err(Fault::View)?;
    Ok(judge_lone_stateless(tx, rule_set, &claims, prior))
}

/// Judge `tx` for the pool holding `pool`, against `chain` under
/// `rule_set` and `policy`: the three calls of the module docs, at the
/// height a block carrying it would connect at. `prior` is a pass the
/// caller already holds for `tx` — the pool's, at a reconcile, or one a
/// submit computed before taking the pool's lock; `None` judges afresh.
///
/// # Errors
///
/// The view's fault, a store invariant observed broken
/// ([`Fault::Corrupt`]), or a [`Fault::Stale`] — a view that answered the
/// claim's read and the comparison's read from different chains. None is a
/// judgement about the transaction.
pub fn judge<'id, V: ChainView<'id>>(
    tx: &Transaction,
    chain: &V,
    pool: &KeyImages,
    rule_set: &RuleSet,
    policy: &AdmissionPolicy,
    prior: Option<&StatelessPass>,
) -> Result<Judged, Fault<V::Fault>> {
    let pass = match stateless(tx, chain, rule_set, prior)? {
        Ok(pass) => pass,
        Err(refused) => return Ok(Judged::Stateless(refused)),
    };
    let connecting = Tip::connecting_height(chain.tip().map_err(Fault::View)?.as_ref());
    let view = PoolView::new(chain, pool);
    let against = match tx_against(
        tx,
        TxSlot::Lone,
        &view,
        rule_set,
        pass.proven(),
        FormAttempt::FIRST,
    )? {
        Ok(against) => against,
        Err(refused) => return Ok(Judged::Chain(refused)),
    };

    let floors = match relay_floor_window(chain, connecting)? {
        AtHeight::Recorded(floors) => floors,
        // The window ends at the connecting height read off this same view,
        // so a view that holds still never answers this. One that moved
        // below it prices nothing, and CEN-M3 refuses an empty window: the
        // transaction is refused, never admitted unpriced.
        AtHeight::AboveTip => Vec::new(),
    };
    Ok(match policy_form(tx, policy, &floors) {
        Err(refused) => Judged::Policy(refused),
        Ok(policy) => Judged::Admitted {
            pass: Box::new(pass),
            against,
            policy,
        },
    })
}

#[cfg(test)]
#[path = "door_tests.rs"]
mod door_tests;
