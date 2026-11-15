// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where an output stands for this wallet: one classifier (A17).
//!
//! An output is **spendable** when a send could use it at the wallet's
//! synced tip: it is not spent, not unspendable, not under an in-flight
//! send's lock, not parked by the user, and its leaf is in the tree of the
//! reference block a wallet at that tip anchors to
//! ([`shekyl_curve_tree::in_tree_at_reference`] on
//! [`shekyl_curve_tree::select_reference_height`]). The predicate is the
//! curve tree's; nothing here restates it as a sum of heights.
//!
//! The balance (`shekyl-scanner`'s `BalanceSummary`), the spendable views
//! ([`TransferDetails::is_spendable`], `LedgerBlock::spendable_outputs`) and
//! the send path's candidate partition (`shekyl-engine-core`) all call
//! [`TransferDetails::state`], so the balance says spendable exactly when a
//! build can select the output. The send path applies its tree gate (is the
//! wallet's copy of the tree built to the reference yet?) after the
//! classifier: that is the wallet's state, not the money's, and an output
//! spendable by the rule stays spendable while the tree catches up.
//!
//! **Placement (rule 18).** An output's state is transform-shaped: a function
//! of its row ([`TransferDetails`], defined here), the journal's locks
//! ([`InFlightSpendLocks`], derived here) and the reference rule (defined in
//! `shekyl-curve-tree`, which this crate depends on; the tree depends on
//! nothing of the wallet's). It lives with the owner of its inputs, below
//! both of its consumers: the scanner's balance and the engine's send path
//! depend on this crate, and neither could host it for the other.

use shekyl_types::{BlockCount, BlockHeight};

use crate::send_journal_block::InFlightSpendLocks;
use crate::transfer::TransferDetails;

/// The reference rule a wallet at one synced tip spends against: the tip,
/// and the reference block it anchors to. Built once per read and handed to
/// [`TransferDetails::state`] for every row, so a balance and a build at
/// the same tip classify by the same reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendHorizon {
    tip: BlockHeight,
    reference: Option<BlockHeight>,
}

impl SpendHorizon {
    /// The horizon of a wallet synced to `tip`. Below
    /// [`shekyl_curve_tree::REF_ANCHOR_AGE`] the chain anchors no
    /// reference, and nothing is spendable yet.
    #[must_use]
    pub fn at_tip(tip: BlockHeight) -> Self {
        Self {
            tip,
            reference: shekyl_curve_tree::select_reference_height(tip),
        }
    }

    /// The synced tip this horizon is at.
    #[must_use]
    pub const fn tip(self) -> BlockHeight {
        self.tip
    }

    /// The reference block a send built at this tip anchors to, if the
    /// chain is long enough to have one.
    #[must_use]
    pub const fn reference(self) -> Option<BlockHeight> {
        self.reference
    }

    /// Whether an output eligible at `eligible_height` is in the reference
    /// block's tree. Per row on every balance read, so `#[inline]`, like
    /// [`InFlightSpendLocks::contains`].
    #[inline]
    #[must_use]
    pub fn holds(self, eligible_height: BlockHeight) -> bool {
        self.reference
            .is_some_and(|r| shekyl_curve_tree::in_tree_at_reference(eligible_height, r))
    }

    /// Blocks the tip must advance until an output eligible at
    /// `eligible_height` is in the reference block's tree. Never less for a
    /// later eligible height.
    #[inline]
    #[must_use]
    pub fn wait(self, eligible_height: BlockHeight) -> BlockCount {
        shekyl_curve_tree::tip_blocks_until_in_tree(eligible_height, self.tip)
    }
}

/// Where an unspent output stands, or that it is spent. Exactly one holds
/// for every row; [`TransferDetails::state`] decides in this precedence,
/// top first:
///
/// 1. **Spent** — confirmed evidence outranks everything else.
/// 2. **Unspendable** — received, but its leaf does not open to this
///    wallet's keys; no send can ever use it.
/// 3. **InFlight** — an in-flight send of this wallet carries it (the F14
///    lock); its value is that send's outgoing and change.
/// 4. **Parked** — the user took it out of coin selection (`frozen` on the
///    row). Before maturity: parking is the user's decision, maturity is
///    the chain's, and parked money stays parked when it matures.
/// 5. **Incoming** — received and not yet in the reference block's tree,
///    with the blocks until it is.
/// 6. **Spendable** — a send could use it now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputState {
    /// Spent on chain.
    Spent,
    /// Received but never spendable by this wallet.
    Unspendable,
    /// Carried by an in-flight send of this wallet.
    InFlight,
    /// Parked by the user: held in the balance, out of coin selection.
    Parked,
    /// Received; spendable once the tip advances `wait` blocks.
    Incoming {
        /// Blocks until the output is in the reference block's tree.
        wait: BlockCount,
    },
    /// A send could use it at this tip.
    Spendable,
}

impl TransferDetails {
    /// This output's state at `horizon`, given the journal's in-flight
    /// locks: the one classifier (see the module docs and
    /// [`OutputState`] for the precedence).
    #[inline]
    #[must_use]
    pub fn state(&self, horizon: SpendHorizon, locks: &InFlightSpendLocks) -> OutputState {
        if self.spent {
            OutputState::Spent
        } else if self.unspendable.is_some() {
            OutputState::Unspendable
        } else if locks.contains(self.global_output_index) {
            OutputState::InFlight
        } else if self.frozen {
            OutputState::Parked
        } else if horizon.holds(self.eligible_height) {
            OutputState::Spendable
        } else {
            OutputState::Incoming {
                wait: horizon.wait(self.eligible_height),
            }
        }
    }
}

#[cfg(test)]
#[path = "output_state_tests.rs"]
mod tests;
