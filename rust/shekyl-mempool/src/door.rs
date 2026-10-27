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
//! Steps 2 and 3 read the view step 1's claim was read off. A
//! [`Stale`](shekyl_chain_rules::Stale) from that comparison is the
//! validator's, and comes back inside [`DoorFault::Chain`]. A relay-floor
//! window the tip has dropped under is [`DoorFault::TipMoved`]: the
//! transaction is unjudged. The floors the policy sees are floors the
//! chain recorded.

use shekyl_chain_rules::{
    judge_lone_stateless, policy_form, relay_floor_window, tx_against, AdmissionPolicy, AtHeight,
    ChainView, Fault, FormAttempt, InvalidBlock, PolicyCoverage, PolicyRefused, ReferenceClaims,
    RuleCoverage, RuleSet, StatelessPass, Tip, TxSlot, ViewRead,
};
use shekyl_types::BlockHeight;
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

/// Why the door could not judge. Never a judgement about the transaction.
///
/// A [`Fault`] is the validator's: the view failed, a store invariant
/// broke, or a premise of block admission went stale. A tip that dropped
/// under the relay-floor window is this door's own fact. [`Stale`](shekyl_chain_rules::Stale)
/// tells a driver to redo `form`, and the pool door is not `form`.
/// [`Fault::Corrupt`] is data no conforming store holds; a moved tip is a
/// chain that moved, and a corrupt arm reaching a connect would halt the
/// writer. The policy's empty window is CEN-M3, a fee refusal, so the
/// floors handed to it are floors the chain recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoorFault<F> {
    /// The validator could not judge against this view.
    Chain(Fault<F>),
    /// The window was read at `asked`, and that height was above the tip.
    /// `now` is the connecting height read again afterwards. The
    /// transaction is unjudged; the caller reads the chain again and judges
    /// once more. Equal heights stay this fault: the window was not priced,
    /// and nothing fills it in afterwards.
    TipMoved {
        /// The connecting height the window was read at.
        asked: BlockHeight,
        /// The connecting height read again after the window answered
        /// [`AtHeight::AboveTip`].
        now: BlockHeight,
    },
}

/// The floors `window` recorded at `asked`, or why it priced none.
///
/// `now` is the connecting height a caller re-read after [`AtHeight::AboveTip`].
/// A recorded window passes through. An absent one is [`DoorFault::TipMoved`]
/// at `(asked, now)`. A view fault stays the validator's [`DoorFault::Chain`].
fn priced_floors<F>(
    window: Result<AtHeight<Vec<u64>>, ViewRead<F>>,
    asked: BlockHeight,
    now: BlockHeight,
) -> Result<Vec<u64>, DoorFault<F>> {
    match window {
        Ok(AtHeight::Recorded(floors)) => Ok(floors),
        Ok(AtHeight::AboveTip) => Err(DoorFault::TipMoved { asked, now }),
        Err(read) => Err(DoorFault::Chain(read.into())),
    }
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
/// [`DoorFault::Chain`] for the view's fault, a store invariant observed
/// broken ([`Fault::Corrupt`]), or a [`Fault::Stale`] — the claim's read
/// and the comparison's read answered from different chains.
/// [`DoorFault::TipMoved`] when the relay-floor window's height is above
/// the tip. None of these is a judgement about the transaction.
pub fn judge<'id, V: ChainView<'id>>(
    tx: &Transaction,
    chain: &V,
    pool: &KeyImages,
    rule_set: &RuleSet,
    policy: &AdmissionPolicy,
    prior: Option<&StatelessPass>,
) -> Result<Judged, DoorFault<V::Fault>> {
    let pass = match stateless(tx, chain, rule_set, prior).map_err(DoorFault::Chain)? {
        Ok(pass) => pass,
        Err(refused) => return Ok(Judged::Stateless(refused)),
    };
    let connecting = Tip::connecting_height(
        chain
            .tip()
            .map_err(|fault| DoorFault::Chain(Fault::View(fault)))?
            .as_ref(),
    );
    let view = PoolView::new(chain, pool);
    let against = match tx_against(
        tx,
        TxSlot::Lone,
        &view,
        rule_set,
        pass.proven(),
        FormAttempt::FIRST,
    )
    .map_err(DoorFault::Chain)?
    {
        Ok(against) => against,
        Err(refused) => return Ok(Judged::Chain(refused)),
    };

    // The window ends at `connecting`. A view that holds still records it.
    // One whose tip dropped answers [`AtHeight::AboveTip`]; the height read
    // again is what the caller retries against. The policy never sees an
    // empty window manufactured for that answer.
    let window = relay_floor_window(chain, connecting);
    let now = if matches!(window, Ok(AtHeight::AboveTip)) {
        Tip::connecting_height(
            chain
                .tip()
                .map_err(|fault| DoorFault::Chain(Fault::View(fault)))?
                .as_ref(),
        )
    } else {
        connecting
    };
    let floors = priced_floors(window, connecting, now)?;
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
