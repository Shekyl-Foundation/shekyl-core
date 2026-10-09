// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's coinbase pricer: [`quote_emission`] once per pass, the
//! template's settle loop, the shared [`REPRICING_PASSES`] budget.
//!
//! A fixture pays what CEN-F18 will require of it on the view it will be
//! judged against. The arithmetic is the validator's ([`quote_emission`]
//! calls [`crate::rules::reward::price`]); this module only re-pays the
//! first coinbase output with the owed amount and repeats while that
//! amount's varint moves the block weight. "Re-pays", not "writes": the
//! fixture coinbase is a real output to the harness miner, so the amount
//! carries a commitment and an encrypted amount with it, and
//! [`shekyl_harness_wallet::coinbase::repay`] re-derives all three
//! together — a patched amount over a stale commitment would be an
//! output no wallet could spend.

use shekyl_economics::REPRICING_PASSES;
use shekyl_harness_wallet::coinbase::repay;
use shekyl_harness_wallet::MinerWallet;
use shekyl_types::BlockHeight;

use super::MockChain;
use crate::block::Candidate;
use crate::fault::ViewRead;
use crate::rules::reward::quote_emission;
use crate::view::{ChainView, Tip};

/// [`priced_at`] at the height `view`'s tip says a candidate connects at.
///
/// A view that answers no tip is genesis. The view's fault and a corrupt
/// parent read are both returned: a missing record is not an F14 refusal,
/// and it must not leave the coinbase untouched as though the block had
/// been priced.
///
/// # Errors
///
/// [`ViewRead`] from the tip read or from [`quote_emission`].
pub fn priced<'id, V: ChainView<'id>>(
    view: &V,
    candidate: Candidate,
) -> Result<Candidate, ViewRead<V::Fault>> {
    let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
    priced_at(view, connecting, candidate)
}

/// `candidate` with its coinbase paying what CEN-F18 requires on `view` at
/// `connecting`.
///
/// At genesis the configured emission stands (F11): the coinbase is
/// returned as it came — a zero coinbase stays zero, an endowed one is
/// kept — after one quote, so a view fault or a corrupt parent read is
/// still [`Err`]. Above genesis, a candidate the reward chain refuses
/// before F18's equality check — over twice the median (F14), a fee sum
/// that does not fit (F17), an owed or accrual overflow — is returned as
/// it stands, including an amount an earlier pass of this loop already
/// wrote. A view fault or a corrupt parent read is [`Err`].
///
/// Below the median the second pass settles. A pair that will not meet
/// within [`REPRICING_PASSES`] is a penalty-boundary shape no fixture asks
/// for, and panics rather than pays a figure F18 would refuse.
///
/// # Errors
///
/// [`ViewRead`] from [`quote_emission`].
pub fn priced_at<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    mut candidate: Candidate,
) -> Result<Candidate, ViewRead<V::Fault>> {
    // Genesis: the configured coinbase stands (F11). Quote once so a
    // corrupt parent read is still a fault, and do not rewrite the amount.
    if connecting.is_zero() {
        // The quote surfaces a view fault or a corrupt parent read. Both
        // verdicts leave the coinbase as it came (F11): a refusal before
        // the equality check is not a reason to rewrite it.
        match quote_emission(view, connecting, &candidate)? {
            Ok(_) | Err(_) => return Ok(candidate),
        }
    }
    for _ in 0..REPRICING_PASSES {
        if !settle_one(view, connecting, &mut candidate)? {
            return Ok(candidate);
        }
    }
    match quote_emission(view, connecting, &candidate)? {
        Ok(paid) => match first_amount(&candidate) {
            Some(amount) if amount == paid.owed.to_raw() => Ok(candidate),
            Some(amount) => panic!(
                "the fixture's coinbase does not settle: priced at {} carrying {amount} \
                 (a penalty-boundary shape no fixture asked for)",
                paid.owed.to_raw()
            ),
            None => Ok(candidate),
        },
        Err(_) => Ok(candidate),
    }
}

/// [`priced_at`] on `chain`'s tip — for a fixture that replaced the
/// coinbase [`super::fixture::candidate_on`] had already priced and needs
/// it priced again.
///
/// The mock's view fault is [`core::convert::Infallible`]. A corrupt read
/// is a bug in the mock's records.
pub fn repriced(chain: &MockChain, candidate: Candidate) -> Candidate {
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    on_mock(chain, connecting, candidate)
}

/// [`priced_at`] for [`super::fixture::repriced`]: the caller already holds
/// a block it believes is priceable, so a corrupt parent read is a broken
/// mock and panics with the invariant it broke. The mock's view fault is
/// [`core::convert::Infallible`].
pub(super) fn on_mock(
    chain: &MockChain,
    connecting: BlockHeight,
    candidate: Candidate,
) -> Candidate {
    chain.with_view(|view| match priced_at(&view, connecting, candidate) {
        Ok(candidate) => candidate,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(corrupt)) => panic!("the mock's view is corrupt: {corrupt:?}"),
    })
}

/// [`priced_at`] for [`super::fixture::candidate_on`].
///
/// A corrupt parent read leaves the coinbase as built. `candidate_on` is
/// how a test hands that view to `validate`, and the fault is `validate`'s
/// to report — a harness panic would hide the row the test planted.
/// The mock's view fault is [`core::convert::Infallible`].
pub(super) fn for_candidate(
    chain: &MockChain,
    connecting: BlockHeight,
    candidate: Candidate,
) -> Candidate {
    let as_built = candidate.clone();
    chain.with_view(|view| match priced_at(&view, connecting, candidate) {
        Ok(priced) => priced,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(_)) => as_built,
    })
}

/// Re-pay the first output with `owed` when it differs.
///
/// `Ok(true)` means the amount changed and the caller should price again.
/// `Ok(false)` means the candidate is done: it already pays `owed`, it has
/// no coinbase output to pay, or the reward chain refused it before F18's
/// equality.
fn settle_one<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    candidate: &mut Candidate,
) -> Result<bool, ViewRead<V::Fault>> {
    let Ok(paid) = quote_emission(view, connecting, candidate)? else {
        return Ok(false);
    };
    if first_amount(candidate) == Some(paid.owed.to_raw()) {
        return Ok(false);
    }
    Ok(repay(
        &mut candidate.block.miner_transaction,
        MinerWallet::harness().recipient(),
        paid.owed.to_raw(),
    ))
}

fn first_amount(candidate: &Candidate) -> Option<u64> {
    candidate
        .block
        .miner_transaction
        .prefix
        .outputs
        .first()
        .map(|output| output.amount)
}
