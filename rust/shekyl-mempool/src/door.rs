// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool door: the validator's own judgement of one transaction, and
//! nothing else (DRS-E5 PR-b b2; `DRS_E5_POOL_ALT_PRUNE.md` §2.2).
//!
//! Three calls, in order:
//!
//! 1. [`judge_slot_stateless`] at [`TxSlot::Lone`] — the function `form`
//!    runs at every slot: `tx_form` (CEN-M2: the full NIC set), the
//!    signatures, the proofs against the claim read off this chain
//!    ([`ReferenceClaims::for_transaction`]), and at `Lone` the range proof
//!    as a batch of one.
//! 2. [`tx_against`] at `Lone` over [`PoolView`] — the view-bound half
//!    `validate` runs per slot, with the pool's key images added (CEN-M6,
//!    CEN-M7); it compares the chain's `(height, root)` at the reference
//!    with the claim step 1 verified.
//! 3. [`policy_form`] — CEN-M3, M4 and M5 over the relay floor window at
//!    the connecting height.
//!
//! The answer says which half refused, because the pool treats them
//! differently: a stateless or policy refusal is final, while a refusal by
//! the chain-bound half is what CEN-K10 keeps a transaction returned from a
//! popped block for — a later reorg may make it valid again. Step 3 runs
//! whatever step 2 answered, and a chain-bound refusal carries the policy's
//! refusal beside it: a policy refusal is final in this pool, so a
//! transaction the policy also refuses is not kept on the chain-bound
//! refusal's account.
//!
//! Every input is read off one chain view, so the claim and the chain it
//! is compared with cannot disagree: a [`Stale`](shekyl_chain_rules::Stale)
//! here is a view that moved under its reader, and comes back as the fault.

use shekyl_chain_rules::{
    judge_slot_stateless, policy_form, relay_floor_window, tx_against, AdmissionPolicy, AtHeight,
    ChainView, Fault, FormAttempt, InvalidBlock, PolicyCoverage, PolicyRefused, ReferenceClaims,
    RuleCoverage, RuleSet, Tip, TxSlot, VerifiedReference,
};
use shekyl_wire::Transaction;

use crate::view::{KeyImages, PoolView};

/// What the door decided about one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Judged {
    /// Every row passed.
    Admitted {
        /// What the proof verified against — CEN-M8's anchor — or `None`
        /// for a transaction whose judgement verified no reference.
        proven: Option<VerifiedReference>,
        /// The consensus rows step 1 recorded.
        stateless: RuleCoverage,
        /// The consensus rows step 2 recorded.
        against: RuleCoverage,
        /// The policy rows step 3 recorded.
        policy: PolicyCoverage,
    },
    /// Refused on the transaction's bytes (step 1): no chain admits it.
    Stateless(InvalidBlock),
    /// Refused by the chain-bound half (step 2), against this chain.
    Chain {
        /// The consensus refusal.
        refused: InvalidBlock,
        /// The admission policy's refusal too, when it refuses (step 3).
        policy: Option<PolicyRefused>,
    },
    /// Admitted by the consensus rows and refused by the admission policy
    /// (step 3).
    Policy(PolicyRefused),
}

/// Judge `tx` for the pool holding `pool`, against `chain` under
/// `rule_set` and `policy`: the three calls of the module docs, at the
/// height a block carrying `tx` would connect at. `cached` is CEN-M8's
/// cache — the triple the pool recorded when it last admitted `tx`, at a
/// re-admission; `None` for a transaction the pool has not judged.
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
    cached: Option<VerifiedReference>,
) -> Result<Judged, Fault<V::Fault>> {
    let connecting = Tip::connecting_height(chain.tip().map_err(Fault::View)?.as_ref());
    let claims = ReferenceClaims::for_transaction(chain, connecting, tx).map_err(Fault::View)?;

    let mut stateless = RuleCoverage::EMPTY;
    let proven =
        match judge_slot_stateless(tx, TxSlot::Lone, rule_set, &claims, cached, &mut stateless) {
            Ok(proven) => proven,
            Err(refused) => return Ok(Judged::Stateless(refused)),
        };

    let view = PoolView::new(chain, pool);
    let against = tx_against(
        tx,
        TxSlot::Lone,
        &view,
        rule_set,
        proven,
        FormAttempt::FIRST,
    )?;

    let floors = match relay_floor_window(chain, connecting)? {
        AtHeight::Recorded(floors) => floors,
        // The window ends at the connecting height read off this same view,
        // so a view that holds still never answers this. One that moved
        // below it prices nothing, and CEN-M3 refuses an empty window: the
        // transaction is refused, never admitted unpriced.
        AtHeight::AboveTip => Vec::new(),
    };
    Ok(match (against, policy_form(tx, policy, &floors)) {
        (Err(refused), policy) => Judged::Chain {
            refused,
            policy: policy.err(),
        },
        (Ok(_), Err(refused)) => Judged::Policy(refused),
        (Ok(against), Ok(policy)) => Judged::Admitted {
            proven,
            stateless,
            against,
            policy,
        },
    })
}

#[cfg(test)]
#[path = "door_tests.rs"]
mod door_tests;
