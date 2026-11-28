// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which ladder fee a leftover pays, and the change that fee leaves.
//!
//! A transaction pays exactly one of the directive's two fees. The fee is
//! cleartext on chain, and a wallet that pays a ladder value hides in that
//! rung's cohort; one that pays its leftover marks itself
//! (`FEE_LADDER_DERIVATION.md` W3).
//!
//! - The leftover equals the no-change fee: that fee, and no change output.
//! - The leftover covers the with-change fee and at least [`MIN_CHANGE`]:
//!   that fee, and the rest as change.
//! - Anything between them, including a leftover equal to the with-change
//!   fee, is [`FeeVariantFault::Short`]. A change of zero would drop the
//!   output while the fee stayed sized for it.
//! - No with-change fee means the payments already fill the output limit.
//!   A leftover above the no-change fee would need a change output the
//!   transaction cannot carry ([`FeeVariantFault::TooManyOutputs`]).
//!
//! [`selection_target`] is the payments, the with-change fee and
//! [`MIN_CHANGE`]. A selection that covered it never produces
//! [`FeeVariantFault::Short`]. The signer applies [`fee_and_change`] to the
//! leftover and refuses what the build should not have handed it. A leftover
//! inside one dust threshold of the with-change fee used to take the
//! no-change fee and leave the rest unaccounted, so the transaction did not
//! balance (A16).

use std::num::NonZeroU64;

use shekyl_tx_builder::MAX_OUTPUTS;
use shekyl_units::AtomicUnits;

use super::error::SendError;
use super::traits::key::FeeDirective;

/// The least change a with-change transaction carries: one atomic unit.
pub(crate) const MIN_CHANGE: NonZeroU64 = NonZeroU64::MIN;

/// The fee a signing pass carries, and the change output beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PricedChange {
    /// The ladder fee the transaction pays.
    pub fee: u64,
    /// The change output. Absent when the transaction pays the no-change fee.
    pub change: Option<NonZeroU64>,
}

/// Why a leftover is not one of the directive's two fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeeVariantFault {
    /// The leftover is not the no-change fee and does not cover the
    /// with-change fee plus [`MIN_CHANGE`].
    Short {
        /// Atomic units the leftover lacks of the fee it was measured against.
        shortfall: u64,
    },
    /// A change output would pass [`MAX_OUTPUTS`].
    TooManyOutputs {
        /// One past [`MAX_OUTPUTS`]: the output the transaction cannot carry.
        count: usize,
    },
}

/// The fee and the change `leftover` (the inputs less the payments) pays
/// from `directive`.
pub(crate) fn fee_and_change(
    leftover: u64,
    directive: &FeeDirective,
) -> Result<PricedChange, FeeVariantFault> {
    if leftover == directive.fee_no_change {
        return Ok(PricedChange {
            fee: directive.fee_no_change,
            change: None,
        });
    }
    let short_of = |fee: u64| FeeVariantFault::Short {
        shortfall: fee.saturating_sub(leftover),
    };
    if leftover < directive.fee_no_change {
        return Err(short_of(directive.fee_no_change));
    }
    match directive.fee_with_change {
        Some(fee_with_change) => match NonZeroU64::new(leftover.saturating_sub(fee_with_change)) {
            Some(change) => Ok(PricedChange {
                fee: fee_with_change,
                change: Some(change),
            }),
            None => Err(short_of(fee_with_change.saturating_add(MIN_CHANGE.get()))),
        },
        None => Err(FeeVariantFault::TooManyOutputs {
            count: MAX_OUTPUTS + 1,
        }),
    }
}

/// What a selection must cover: the payments, the with-change fee and
/// [`MIN_CHANGE`].
///
/// # Errors
///
/// [`SendError::InvalidRecipient`] when the sum does not fit in `u64`.
pub(crate) fn selection_target(
    payments: AtomicUnits,
    fee_with_change: AtomicUnits,
) -> Result<AtomicUnits, SendError> {
    payments
        .checked_add(fee_with_change)
        .and_then(|total| total.checked_add(AtomicUnits::from_raw(MIN_CHANGE.get())))
        .ok_or(SendError::InvalidRecipient {
            reason: "amount + fee overflowed u64",
        })
}

/// The send path's fee convergence over a selection: the one loop every
/// spend uses whose fee depends on how many inputs it selects (the ordinary
/// send, and the `P`-lane drain priced on its own weight).
///
/// Price one input and select for the target at that fee; price the count
/// selected, and if the fee rose, select once more at the new target. The
/// fee returned is the final selection's own. The caller checks that the
/// selection covers the target at that fee, and names the shortfall in its
/// own terms.
///
/// `fee_for(n)` is the fee of the spend with `n` inputs; `target_for(fee)` is
/// what a selection must cover at that fee; `select(target)` selects for it.
///
/// # Errors
///
/// Whatever `fee_for`, `target_for` or `select` returns.
pub(crate) fn converge_selection<S, E>(
    fee_for: impl Fn(usize) -> Result<AtomicUnits, E>,
    target_for: impl Fn(AtomicUnits) -> Result<AtomicUnits, E>,
    mut select: impl FnMut(AtomicUnits) -> Result<S, E>,
    selected_count: impl Fn(&S) -> usize,
) -> Result<(S, AtomicUnits), E> {
    let fee_a = fee_for(1)?;
    let mut selected = select(target_for(fee_a)?)?;
    let fee_b = fee_for(selected_count(&selected))?;
    if fee_b > fee_a {
        selected = select(target_for(fee_b)?)?;
    }
    let fee = fee_for(selected_count(&selected))?;
    Ok((selected, fee))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(fee_no_change: u64, fee_with_change: Option<u64>) -> FeeDirective {
        FeeDirective {
            fee_no_change,
            fee_with_change,
        }
    }

    /// Every leftover the rule accepts balances at one of the two ladder
    /// fees: inputs = payments + fee + change. Bites if a leftover that is
    /// not exactly the no-change fee falls back to that fee.
    #[test]
    fn every_accepted_leftover_balances_at_a_ladder_fee() {
        let directive = directive(700, Some(900));
        for leftover in [901, 950, 1_000, 5_000, u64::MAX / 2] {
            let priced = fee_and_change(leftover, &directive).expect("covered");
            assert_eq!(priced.fee, 900, "leftover {leftover}");
            let change = priced.change.expect("a change output").get();
            assert!(change >= MIN_CHANGE.get(), "leftover {leftover}");
            assert_eq!(priced.fee + change, leftover);
        }
        let exact = fee_and_change(700, &directive).expect("exact");
        assert_eq!(exact.fee, 700);
        assert_eq!(exact.change, None);
    }

    /// A leftover no ladder fee balances is refused. A leftover equal to
    /// the with-change fee is one unit short of a change output, so the fee
    /// would be sized for an output the transaction does not carry.
    #[test]
    fn a_leftover_no_ladder_fee_balances_is_refused() {
        let directive = directive(700, Some(900));
        for leftover in [0, 699, 701, 899, 900] {
            assert!(
                matches!(
                    fee_and_change(leftover, &directive),
                    Err(FeeVariantFault::Short { .. })
                ),
                "leftover {leftover}"
            );
        }
    }

    /// At the output limit only the exact no-change leftover is priced. A
    /// leftover above it names the output the transaction cannot carry.
    #[test]
    fn at_the_output_limit_only_the_exact_leftover_is_priced() {
        let directive = directive(700, None);
        let exact = fee_and_change(700, &directive).expect("exact");
        assert_eq!(exact.fee, 700);
        assert_eq!(exact.change, None);
        for leftover in [701, 900, 5_000, u64::MAX] {
            assert!(
                matches!(
                    fee_and_change(leftover, &directive),
                    Err(FeeVariantFault::TooManyOutputs { count }) if count == MAX_OUTPUTS + 1
                ),
                "leftover {leftover}"
            );
        }
        assert!(matches!(
            fee_and_change(699, &directive),
            Err(FeeVariantFault::Short { shortfall: 1 })
        ));
    }

    /// The selection target is the with-change fee plus one unit of change,
    /// so the signer's rule accepts every leftover a successful selection
    /// can hand it.
    #[test]
    fn the_selection_target_covers_the_least_change() {
        let payments = AtomicUnits::from_raw(1_000);
        let fee = AtomicUnits::from_raw(900);
        let target = selection_target(payments, fee).expect("fits");
        assert_eq!(target.to_raw(), 1_000 + 900 + MIN_CHANGE.get());
    }
}
