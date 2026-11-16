// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The balance and its legs (A17; Rick, 2026-11-15).
//!
//! **balance = spendable + incoming**:
//!
//! - **spendable** — what a send could use at the wallet's synced tip:
//!   the classifier's `Spendable` ([`TransferDetails::state`]).
//! - **incoming** — received outputs not yet spendable by that rule, plus
//!   the change of each in-flight send of this wallet, from dispatch until
//!   the change output is scanned; from then it is a received output,
//!   counted by the rule. [`BalanceSummary::incoming_wait`] is the blocks
//!   until the soonest on-chain incoming output becomes spendable, absent
//!   (not zero) when no incoming output is on chain.
//!
//! Beside the balance, never in it: **outgoing**, Σ (recipients + fee) of
//! the in-flight sends, and **unspendable**, outputs that are this wallet's
//! but whose leaf does not open to its keys. An in-flight send's inputs
//! are in no leg: their value is that send's outgoing plus its change.
//!
//! The tree rebuild is the wallet's state, not the money's: an output
//! spendable by the rule stays in `spendable` while the wallet's tree
//! catches up, and a send in that window is refused with its own error.

use std::collections::BTreeSet;

use shekyl_engine_state::{OutputState, SendJournalBlock, SpendHorizon};
use shekyl_types::{BlockCount, BlockHeight};
use shekyl_units::AtomicUnits;

use crate::transfer::TransferDetails;

/// The balance's legs at one synced tip. Each holds one quantity, and no
/// field is a sum of others: [`Self::balance`] is computed from them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BalanceSummary {
    /// What a send could use now.
    pub spendable: AtomicUnits,
    /// Received and not yet spendable, plus in-flight sends' change.
    pub incoming: AtomicUnits,
    /// Blocks until the soonest on-chain incoming output is spendable;
    /// `None` when no incoming output is on chain (only change in flight,
    /// or nothing incoming).
    pub incoming_wait: Option<BlockCount>,
    /// Σ (recipients + fee) of the in-flight sends. Beside the balance.
    pub outgoing: AtomicUnits,
    /// This wallet's but never spendable by it. Beside the balance.
    pub unspendable: AtomicUnits,
}

/// Accumulate a balance bucket. A wallet's unspent total is bounded by the
/// money supply (`< u64::MAX` atomic units), so overflow here is not a
/// reachable condition for valid state — it is corrupted-state evidence and
/// must surface loudly (per ATOMIC_UNITS_NEWTYPE.md §7.2: `None` is a bug,
/// never `unwrap_or(ZERO)`).
fn accumulate(bucket: AtomicUnits, amount: AtomicUnits) -> AtomicUnits {
    bucket
        .checked_add(amount)
        .expect("balance overflow: unspent output total exceeds u64 atomic units (corrupted state)")
}

impl BalanceSummary {
    /// The balance: spendable + incoming.
    #[must_use]
    pub fn balance(&self) -> AtomicUnits {
        accumulate(self.spendable, self.incoming)
    }

    /// The legs of `transfers` at `horizon`, with `journal`'s in-flight
    /// sends. Every unspent row is classified once
    /// ([`TransferDetails::state`]); an in-flight send ([`shekyl_engine_state::SendRecord::is_in_flight`])
    /// adds its outgoing and its change until one of its inputs is spent in
    /// `transfers` — the scan that marks an input spent is the scan that
    /// receives the change, so from then the change is a row like any
    /// other.
    #[must_use]
    pub fn compute(
        transfers: &[TransferDetails],
        horizon: SpendHorizon,
        journal: &SendJournalBlock,
    ) -> Self {
        let locks = journal.spend_locks();
        // The in-flight sends' inputs (the lock set's keys) that a scan has
        // already spent. Walked only when a send is in flight, which the
        // common read has none of.
        let scanned: BTreeSet<u64> = if locks.is_empty() {
            BTreeSet::new()
        } else {
            transfers
                .iter()
                .filter(|td| td.spent && locks.contains(td.global_output_index))
                .map(|td| td.global_output_index.to_raw())
                .collect()
        };

        // The legs are summed in locals and written once, so the loop keeps
        // them in registers (`hot_path_bench_balance_compute`).
        let (mut spendable, mut incoming, mut unspendable) =
            (AtomicUnits::ZERO, AtomicUnits::ZERO, AtomicUnits::ZERO);
        // The wait grows with the eligible height, so the soonest incoming
        // output's wait is the wait at the least eligible height: taken
        // once, after the walk.
        let mut first_incoming: Option<BlockHeight> = None;
        for td in transfers {
            let amount = td.amount();
            match td.state(horizon, &locks) {
                OutputState::Spent | OutputState::InFlight => {}
                OutputState::Unspendable => unspendable = accumulate(unspendable, amount),
                OutputState::Incoming { .. } => {
                    incoming = accumulate(incoming, amount);
                    first_incoming = Some(
                        first_incoming.map_or(td.eligible_height, |h| h.min(td.eligible_height)),
                    );
                }
                OutputState::Spendable => spendable = accumulate(spendable, amount),
            }
        }
        let mut summary = Self {
            spendable,
            incoming,
            incoming_wait: first_incoming.map(|h| horizon.wait(h)),
            outgoing: AtomicUnits::ZERO,
            unspendable,
        };

        for (_, row) in journal.in_flight() {
            if row
                .inputs
                .iter()
                .any(|input| scanned.contains(&input.gindex))
            {
                continue;
            }
            let outgoing = row
                .outgoing_amount()
                .expect("a recorded send's recipients and fee fit u64 (corrupted state)");
            summary.outgoing = accumulate(summary.outgoing, AtomicUnits::from_raw(outgoing));
            summary.incoming =
                accumulate(summary.incoming, AtomicUnits::from_raw(row.change_amount));
        }
        summary
    }
}

#[cfg(test)]
#[path = "balance_tests.rs"]
mod tests;
