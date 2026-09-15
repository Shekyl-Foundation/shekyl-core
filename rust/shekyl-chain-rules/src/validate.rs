// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three entry points: [`validate`] for a block, [`tx_form`] and
//! [`tx_against`] for one transaction.
//!
//! All three are generic over the view (`V: ChainView<'id>`, never `&dyn`),
//! so DRS-E5's pool decorator implements the trait without this crate naming
//! it, and all three return a fault in the outer position and a verdict in
//! the inner one. Inside a rule, `?` propagates a fault and only a fault; a
//! refusal is always written out as `Ok(Err(InvalidBlock { rule, locus }))`
//! at the site that judged, so the row is named where the decision is made.
//!
//! # Increment 1
//!
//! Zero rules are landed (DRS-D12). The pipeline below is the shape the
//! porting increments fill: block-level rules run first, then each
//! transaction is judged by form and then against the view, coverages are
//! unioned, and the `ChainValid` is minted only after the last rule passed.
//! Today every path reaches the mint with `RuleCoverage::EMPTY`, which is
//! never complete for any rule set — a scaffold verdict is not parity
//! evidence, and nothing that checks can mistake it for one.

use shekyl_wire::Transaction;

use crate::block::{Candidate, ValidatedBlock};
use crate::coverage::RuleCoverage;
use crate::rule_set::RuleSet;
use crate::verdict::{ChainValid, InvalidBlock, TxSlot, Verdict};
use crate::view::ChainView;

/// Judge a candidate block under `rule_set` against `view`.
///
/// Returns, in order of what happened:
///
/// * `Err(fault)` — the view's substrate failed before a verdict was
///   reached. Not a judgement about the block; the caller halts.
/// * `Ok(Err(refused))` — a rule refused. `refused.rule` is the census row,
///   `refused.locus` where in the candidate it pointed.
/// * `Ok(Ok(valid))` — every rule the set enforces passed.
///   `valid.coverage()` records which rows were actually evaluated.
///
/// The miner transaction and each listed transaction are judged by
/// [`tx_form`] then [`tx_against`]; a refusal from either is re-homed from
/// [`TxSlot::Lone`] to the slot the transaction occupies.
pub fn validate<'id, V: ChainView<'id>>(
    candidate: Candidate,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Verdict<ChainValid<'id>>, V::Fault> {
    let mut coverage = RuleCoverage::EMPTY;

    // Block-level rules (4.A–4.G): none landed in increment 1.

    let miner = (TxSlot::Miner, &candidate.block.miner_transaction);
    let listed = candidate
        .transactions
        .iter()
        .enumerate()
        .map(|(n, tx)| (TxSlot::Listed(n), tx));
    for (slot, tx) in core::iter::once(miner).chain(listed) {
        match judge_tx(tx, view, rule_set)? {
            Ok(tx_coverage) => coverage.union(&tx_coverage),
            Err(refused) => {
                return Ok(Err(InvalidBlock {
                    rule: refused.rule,
                    locus: refused.locus.rehome(slot),
                }));
            }
        }
    }

    Ok(Ok(ChainValid::mint(
        ValidatedBlock::derive(candidate),
        rule_set.id(),
        coverage,
    )))
}

/// Stateless per-transaction rules (census 4.H): everything decidable from
/// the transaction's bytes alone. Shared verbatim by block connect and pool
/// admission.
///
/// A refusal's locus is [`TxSlot::Lone`]; `validate` re-homes it.
pub fn tx_form(tx: &Transaction, rule_set: &RuleSet) -> Verdict<RuleCoverage> {
    // 4.H rules land with their slice (DRS-D12); nothing reads the
    // transaction or the rule set yet.
    let _ = (tx, rule_set);
    Ok(RuleCoverage::EMPTY)
}

/// Stateful per-transaction rules (census 4.I): everything that needs the
/// recorded chain — spent key images, the membership anchor. The pool passes
/// its view decorator here.
///
/// A refusal's locus is [`TxSlot::Lone`]; `validate` re-homes it.
pub fn tx_against<'id, V: ChainView<'id>>(
    tx: &Transaction,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Verdict<RuleCoverage>, V::Fault> {
    // 4.I rules land with their slice (DRS-D12); nothing reads the
    // transaction, the view, or the rule set yet.
    let _ = (tx, view, rule_set);
    Ok(Ok(RuleCoverage::EMPTY))
}

/// [`tx_form`] then [`tx_against`], coverages unioned. The locus of a
/// refusal is left as the callee wrote it.
fn judge_tx<'id, V: ChainView<'id>>(
    tx: &Transaction,
    view: &V,
    rule_set: &RuleSet,
) -> Result<Verdict<RuleCoverage>, V::Fault> {
    let mut coverage = match tx_form(tx, rule_set) {
        Ok(coverage) => coverage,
        Err(refused) => return Ok(Err(refused)),
    };
    Ok(tx_against(tx, view, rule_set)?.map(|against| {
        coverage.union(&against);
        coverage
    }))
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod validate_tests;
