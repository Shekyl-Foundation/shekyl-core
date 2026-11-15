// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The build's view of the wallet's outputs: which a selector may pick, and,
//! when they do not cover the send, which refusal names what is in the way.
//!
//! Each output is classified once by the one classifier
//! ([`shekyl_engine_state::TransferDetails::state`], A17) at the build's
//! horizon, the same horizon its reference block was bound from. The tree
//! gate is applied after the classifier: an output spendable by the rule is
//! a candidate when the wallet's tree has reached the reference, and money
//! waiting on the rebuild otherwise. Outputs reserved by other built,
//! unsubmitted sends are skipped: they are spendable money already promised.

use std::collections::HashSet;

use shekyl_engine_state::{OutputState, SpendHorizon, WalletLedger};
use shekyl_types::BlockHeight;

use shekyl_units::AtomicUnits;

use super::super::error::SendError;
use super::super::output_selector::OutputCandidate;
use super::super::sign_bridge::MIN_CHANGE;
use super::support::TreeSpendGate;
use super::types::OutputId;

/// The wallet's outputs at one horizon, as a build sees them. Amounts are
/// raw atomic units; every total saturates (a wallet's money fits `u64`).
#[derive(Debug, Default)]
pub(super) struct CandidatePartition {
    /// Spendable and covered by the wallet's tree: what a selector may pick.
    pub candidates: Vec<OutputCandidate>,
    /// Σ of the candidates.
    pub spendable_now: u64,
    /// Spendable by the rule while the wallet's tree has not reached the
    /// reference block: the rebuild's money.
    pub pending_rebuild: u64,
    /// Received and not yet spendable, `(eligible_height, amount)` each.
    pub incoming: Vec<(BlockHeight, u64)>,
    /// Σ of [`Self::incoming`].
    pub incoming_total: u64,
    /// Parked by the user: in the balance, never selected.
    pub parked: u64,
}

impl CandidatePartition {
    /// Classify `wallet`'s outputs at `horizon`, skipping those `reserved`
    /// by other builds, with the tree gate applied to the spendable ones.
    pub fn of(
        wallet: &WalletLedger,
        horizon: SpendHorizon,
        tree_gate: TreeSpendGate,
        reserved: &HashSet<OutputId>,
    ) -> Self {
        let locks = wallet.spend_locks();
        let mut partition = Self::default();
        for (index, td) in wallet.ledger.transfers().iter().enumerate() {
            if reserved.contains(&index) {
                continue;
            }
            let amount = td.amount();
            let raw = amount.to_raw();
            match td.state(horizon, &locks) {
                OutputState::Spendable => {
                    // Spendable means the horizon anchors a reference; the
                    // gate asks whether the wallet's tree has reached it.
                    let covered = horizon
                        .reference()
                        .is_some_and(|reference| tree_gate.covers(reference));
                    if covered {
                        partition.spendable_now = partition.spendable_now.saturating_add(raw);
                        partition.candidates.push(OutputCandidate { index, amount });
                    } else {
                        partition.pending_rebuild = partition.pending_rebuild.saturating_add(raw);
                    }
                }
                OutputState::Incoming { .. } => {
                    partition.incoming_total = partition.incoming_total.saturating_add(raw);
                    partition.incoming.push((td.eligible_height, raw));
                }
                OutputState::Parked => partition.parked = partition.parked.saturating_add(raw),
                OutputState::Spent | OutputState::Unspendable | OutputState::InFlight => {}
            }
        }
        partition
    }

    /// Why the candidates do not cover `needed`, preferring the
    /// soonest-healing explanation (CT-5 §3.2.1 D3, C2):
    ///
    /// 1. **The rebuild** — the tree is still reaching the reference, and
    ///    the money waiting on it closes the gap: it heals as the tree
    ///    advances ([`SendError::SpendUnavailableRebuilding`]).
    /// 2. **Incoming money** — received outputs not yet spendable close the
    ///    gap: it heals as the tip advances, and the refusal names the
    ///    wait until enough of them are spendable
    ///    ([`SendError::OutputNotYetSpendable`]).
    /// 3. **Parked money** — the user's parked outputs close the gap: only
    ///    the user can release them, and the refusal names how much is
    ///    parked ([`SendError::OutputsParked`]).
    /// 4. Otherwise the wallet is short ([`SendError::InsufficientFunds`]):
    ///    `available` is its spendable money (the rebuild's included) plus
    ///    its incoming outputs, less what other built sends reserve. It
    ///    leaves out parked money (arm 3 names it) and the change of
    ///    in-flight sends, which is not an output yet.
    ///
    /// `reference` is the reference block the build anchors to; arm 2 is
    /// reached only when it is set, since incoming outputs exist only
    /// relative to a reference.
    pub fn refusal(&self, needed: u64, reference: Option<BlockHeight>) -> SendError {
        let with_rebuild = self.spendable_now.saturating_add(self.pending_rebuild);
        let available = with_rebuild.saturating_add(self.incoming_total);
        if self.pending_rebuild > 0 && self.spendable_now < needed && with_rebuild >= needed {
            return SendError::SpendUnavailableRebuilding {
                needed,
                spendable_now: self.spendable_now,
                pending_rebuild: self.pending_rebuild,
            };
        }
        if let Some(reference_block_height) = reference {
            if self.incoming_total > 0 && with_rebuild < needed && available >= needed {
                // Report the height by which *enough* incoming outputs are
                // spendable — accumulate soonest first until the shortfall is
                // covered, not just the soonest (which alone may not suffice).
                let shortfall = needed.saturating_sub(with_rebuild);
                let mut by_eligible = self.incoming.clone();
                by_eligible.sort_unstable_by_key(|&(eligible, _)| eligible);
                let mut covered: u64 = 0;
                let mut eligible_height = reference_block_height;
                for (eligible, amount) in by_eligible {
                    eligible_height = eligible;
                    covered = covered.saturating_add(amount);
                    if covered >= shortfall {
                        break;
                    }
                }
                return SendError::OutputNotYetSpendable {
                    eligible_height,
                    reference_block_height,
                    wait_blocks: shekyl_curve_tree::blocks_until_in_tree(
                        eligible_height,
                        reference_block_height,
                    ),
                };
            }
        }
        if self.parked > 0 && available < needed && available.saturating_add(self.parked) >= needed
        {
            return SendError::OutputsParked {
                needed,
                parked: self.parked,
            };
        }
        SendError::InsufficientFunds { needed, available }
    }
}

/// What a selection must cover: the payments, the with-change fee and the
/// least change ([`MIN_CHANGE`]). A leftover that is exactly the with-change
/// fee would leave a change of zero, which the signer refuses
/// (`sign_bridge::fee_and_change`): the fee would be sized for an output
/// the transaction does not carry.
pub(super) fn selection_target(
    payments: AtomicUnits,
    fee_with_change: AtomicUnits,
) -> Result<AtomicUnits, SendError> {
    payments
        .checked_add(fee_with_change)
        .and_then(|v| v.checked_add(AtomicUnits::from_raw(MIN_CHANGE.get())))
        .ok_or(SendError::InvalidRecipient {
            reason: "amount + fee overflowed u64",
        })
}
