// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where an output stands for this wallet: one classifier (A17).
//!
//! An output is **spendable** when a send could use it at the wallet's
//! synced tip: it is not spent, not unspendable, not under an in-flight
//! send's lock, and its leaf is in the tree of the
//! reference block a wallet at that tip anchors to
//! ([`shekyl_curve_tree::in_tree_at_reference`] on
//! [`shekyl_curve_tree::select_reference_height`]). The predicate is the
//! curve tree's; nothing here restates it as a sum of heights.
//!
//! The balance (`shekyl-scanner`'s `BalanceSummary`), the spendable views
//! ([`TransferDetails::is_spendable`], `LedgerBlock::spendable_outputs`) and
//! the send path's candidate partition (`shekyl-engine-core`) all call
//! [`TransferDetails::state`], so the balance says spendable exactly when a
//! build can select the output. The transfer list calls
//! [`TransferDetails::standing`]: confirmed on chain is spendable or
//! incoming, and that split needs the horizon the list does not have. The
//! send path applies its tree gate (is the wallet's copy of the tree built
//! to the reference yet?) after the classifier: that is the wallet's state,
//! not the money's, and an output spendable by the rule stays spendable
//! while the tree catches up.
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
/// 4. **Incoming** — received and not yet in the reference block's tree.
///    [`SpendHorizon::wait`] is how many blocks until it is.
/// 5. **Spendable** — a send could use it now.
///
/// There is no user-set hold: FCMP++ hides which outputs a spend uses, and
/// the wallet's own reservations keep built and staking-held outputs out of
/// selection (`V3_WALLET_DECISION_LOG.md`, 2026-11-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputState {
    /// Spent on chain.
    Spent,
    /// Received but never spendable by this wallet.
    Unspendable,
    /// Carried by an in-flight send of this wallet.
    InFlight,
    /// Received; spendable once [`SpendHorizon::wait`] reaches zero.
    Incoming,
    /// A send could use it at this tip.
    Spendable,
}

/// What keeps an output out of the reference rule, or that nothing does.
///
/// [`TransferDetails::state`] is this plus the horizon. The transfer list
/// stops here: an [`Self::OnChain`] row is confirmed, whether or not it is
/// spendable yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStanding {
    /// Spent on chain.
    Spent,
    /// Received but never spendable by this wallet.
    Unspendable,
    /// Carried by an in-flight send of this wallet.
    InFlight,
    /// Received, not spent, not locked, not unspendable. The horizon splits
    /// this into [`OutputState::Spendable`] or [`OutputState::Incoming`].
    OnChain,
}

impl TransferDetails {
    /// This output's standing given the journal's in-flight locks: the
    /// horizon-free half of the classifier (see [`OutputStanding`]).
    #[inline]
    #[must_use]
    pub fn standing(&self, locks: &InFlightSpendLocks) -> OutputStanding {
        if self.spent {
            OutputStanding::Spent
        } else if self.unspendable.is_some() {
            OutputStanding::Unspendable
        } else if locks.contains(self.global_output_index) {
            OutputStanding::InFlight
        } else {
            OutputStanding::OnChain
        }
    }

    /// This output's state at `horizon`, given the journal's in-flight
    /// locks: [`Self::standing`] plus the reference rule (see the module
    /// docs and [`OutputState`] for the precedence).
    #[inline]
    #[must_use]
    pub fn state(&self, horizon: SpendHorizon, locks: &InFlightSpendLocks) -> OutputState {
        match self.standing(locks) {
            OutputStanding::Spent => OutputState::Spent,
            OutputStanding::Unspendable => OutputState::Unspendable,
            OutputStanding::InFlight => OutputState::InFlight,
            OutputStanding::OnChain if horizon.holds(self.eligible_height) => {
                OutputState::Spendable
            }
            OutputStanding::OnChain => OutputState::Incoming,
        }
    }
}

#[cfg(test)]
#[path = "output_state_tests.rs"]
mod tests;
