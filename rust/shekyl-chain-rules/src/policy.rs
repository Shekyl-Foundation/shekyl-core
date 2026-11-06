// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay/pool admission policy — the policy-flagged census rows
//! ([`PolicyRow`]) the transaction's bytes and the relay floor decide, as
//! one function, [`policy_form`] (DRS-E5 PR-b b1;
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.2).
//!
//! The pool door is three calls, and this is the third: the validator's
//! stateless judgement at `TxSlot::Lone`, then `tx_against` over the pool
//! decorator, then these rows. A policy row is never consensus: a refusal
//! here is a [`PolicyRefused`], which carries a [`PolicyRow`] and cannot
//! be an [`InvalidBlock`](crate::InvalidBlock), and a pass records into a
//! [`PolicyCoverage`], which cannot hold a [`CenRow`](crate::CenRow) (the
//! census's partition by type, `CHAIN_RULES_CRATE.md` §4.1). Nothing in
//! `form` or `validate` calls this module.
//!
//! **One door for every transaction** (`E5-Q1`, reopened in part
//! 2026-10-11): a transaction returned from a popped block is held to these
//! rows exactly as a relayed one is. There is no `kept_by_block` argument
//! to skip them with.
//!
//! The rows here are the three the transaction and the chain's relay floor
//! decide. The pool's own rows — M1 (already held), M6 and M7 (the key
//! images, through the decorator), M9 (the engine's submit), M10
//! (eviction) — are `shekyl-mempool`'s, held there and cited by the
//! registry.

use shekyl_wire::transaction::{Ct, Transaction, MAX_TX_EXTRA};

use crate::census::PolicyRow;
use crate::coverage::PolicyCoverage;
use crate::rule_set::AdmissionPolicy;
use crate::rules::Bound;

/// A transaction the admission policy refuses, and the row that refused
/// it. Not a verdict about any block: a block may carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRefused {
    /// The policy row that refused.
    pub rule: PolicyRow,
}

impl core::fmt::Display for PolicyRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "refused by admission policy {}", self.rule)
    }
}

impl core::error::Error for PolicyRefused {}

/// A type implementing one policy row. The census registry's
/// `implemented(path)` pin reads `ROW` through [`Bound`], so an entry naming
/// another row's type is a compile error (SCW-18), as for a consensus rule.
pub(crate) trait PolicyRule {
    /// The policy row this type implements.
    const ROW: PolicyRow;
}

impl<T: PolicyRule> Bound<PolicyRow> for T {
    const ROW: PolicyRow = T::ROW;
}

/// Run `R`: record its row when it passes, name it when it refuses.
fn judge<R: PolicyRule>(passes: bool, coverage: &mut PolicyCoverage) -> Result<(), PolicyRefused> {
    if passes {
        coverage.insert(R::ROW);
        Ok(())
    } else {
        Err(PolicyRefused { rule: R::ROW })
    }
}

/// CEN-M3: the relay fee floor (FL-R20, FL-R23, FL-R27). The fee must reach
/// `quantized_fee(weight, min floors)`, the floors being `F(h)` over the
/// `G + 1` heights ending at the connecting height
/// ([`relay_floor_window`](crate::relay_floor_window)), and the predicate
/// is `shekyl_economics::relay_floor_admits` — the economics crate's, never
/// restated here. An empty window refuses: no floor is not a floor of zero.
/// No exemption: a returned transaction below the floor is refused as a
/// relayed one is.
pub(crate) struct M3;

impl PolicyRule for M3 {
    const ROW: PolicyRow = PolicyRow::M3;
}

impl M3 {
    fn admits(tx: &Transaction, floors: &[u64]) -> bool {
        // A `Null` ct pays no fee; at `TxSlot::Lone` CEN-H15 has refused it
        // before policy runs, and if it were not, a fee of zero is below
        // every floor.
        let fee = match &tx.ct {
            Ct::Fcmp { fee, .. } => *fee,
            Ct::Null(_) => 0,
        };
        // The consensus weight (serialized size plus the BP+ clawback), the
        // value block weight and the wallet's fee estimate both charge.
        let weight = u64::try_from(tx.weight()).unwrap_or(u64::MAX);
        shekyl_economics::relay_floor_admits(fee, weight, floors)
    }
}

/// CEN-M4: a transaction's `tx.extra` is at most
/// [`MAX_TX_EXTRA`](shekyl_wire::transaction::MAX_TX_EXTRA) (24 576 bytes).
/// The wire's `validate` refuses the same bound as the wallet's pre-check;
/// this is the row the pool answers to. A coinbase never reaches the door
/// (CEN-H5 at `TxSlot::Lone`), and its extra is bounded by grammar (CEN-I20).
pub(crate) struct M4;

impl PolicyRule for M4 {
    const ROW: PolicyRow = PolicyRow::M4;
}

/// CEN-M5: a relayed transaction's `unlock_time` is zero — the relay half
/// of the two-layer unlock ban (`GENESIS_TX_WIRE_FORMAT.md` :888–891); the
/// consensus half is CEN-H16.
pub(crate) struct M5;

impl PolicyRule for M5 {
    const ROW: PolicyRow = PolicyRow::M5;
}

/// The admission policy's rows over one transaction, in census order —
/// CEN-M3 (the fee floor over `floors`), CEN-M4 (the extra cap), CEN-M5
/// (the unlock ban) — the first refusal is the answer. `floors` is the
/// relay floor window at the pool's connecting height, read by the caller
/// off its chain view with [`relay_floor_window`](crate::relay_floor_window).
///
/// `_policy` is the contract's parameter (`DRS_E5_POOL_ALT_PRUNE.md` §2.2),
/// as `tx_form`'s rule set is: every row here reads a frozen constant, and
/// the first row whose bound varies by policy step is its first reader.
///
/// # Errors
///
/// [`PolicyRefused`] naming the first row that refused.
pub fn policy_form(
    tx: &Transaction,
    _policy: &AdmissionPolicy,
    floors: &[u64],
) -> Result<PolicyCoverage, PolicyRefused> {
    let mut coverage = PolicyCoverage::EMPTY;
    judge::<M3>(M3::admits(tx, floors), &mut coverage)?;
    judge::<M4>(tx.prefix.extra.len() <= MAX_TX_EXTRA, &mut coverage)?;
    judge::<M5>(tx.prefix.unlock_time == 0, &mut coverage)?;
    Ok(coverage)
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
