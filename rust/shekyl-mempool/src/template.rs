// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Template selection from the pool (DRS-E5 PR-b b6; `fill_block_template`'s
//! successor): which held transactions a block built on `parent` lists,
//! as a pure function of the pool, the parent's chain and a weight budget.
//!
//! Candidates are what the node shows ([`shown`](crate::shown): public and
//! admitted — a stem-phase transaction is never in a template, nor a kept
//! one), most fee per unit of weight first (ties: the earliest held, then
//! the hash). Each is judged again by [`tx_against`] at `TxSlot::Lone`
//! against the parent, over the parent plus the key images already
//! selected — the view-bound half `validate` will run on the block, so a
//! transaction whose reference has aged out of CEN-I11's window, or whose
//! image the chain has spent since it was admitted, is not selected. Those
//! are returned for CEN-M10 to evict ([`Pool::evict`]). The comparison
//! claim is the anchor the pool recorded (CEN-M8): a parent whose root at
//! the reference moved since is a stale anchor, not a refusal, and the
//! transaction waits for the reconcile to judge it again.
//!
//! The rows that hold across a block's transactions are asked as each is
//! selected: CEN-L1 by the key images already selected (above), and CEN-G7,
//! G9 and G10 — one serve credit per `(P, shard, E)`, one emission claim per
//! `(P, E)`, one bond post per `P` — by the validator's
//! [`BlockArchivalKeys`]. Two transactions each valid against the parent
//! may still be refused together: two JoinMarket posts by one persona,
//! funded by different key images, is the case. The later one is not
//! selected and not evicted — it is valid alone, and a block without the
//! earlier one may list it.
//!
//! The coinbase, the header and the section budget are the template
//! builder's (`shekyl-block-template`); this selects the listed bodies.

use shekyl_chain_rules::{
    tx_against, BlockArchivalKeys, CenRow, ChainView, Fault, FormAttempt, InvalidBlock, RuleSet,
    TxSlot,
};
use shekyl_chain_store::pool::Standing;
use shekyl_types::TxHash;
use shekyl_wire::Transaction;

use crate::pool::{key_images_of, Pool};
use crate::relay::shown;
use crate::view::{KeyImages, PoolView};

/// What [`select`] chose, and what it could not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selected {
    /// The listed bodies, in the order the block lists them.
    pub transactions: Vec<(TxHash, Transaction)>,
    /// Their total weight.
    pub weight: u64,
    /// Their total fee.
    pub fees: u64,
    /// Candidates the parent refused (CEN-M10 evicts them).
    pub refused: Vec<(TxHash, InvalidBlock)>,
    /// Candidates whose recorded anchor the parent no longer claims: not
    /// refused, not selected — the reconcile judges them again.
    pub stale: Vec<TxHash>,
    /// Candidates valid against the parent that a block listing them after
    /// the selected ones is refused on, with the row (G7, G9 or G10): not
    /// selected, and not evicted.
    pub conflicted: Vec<(TxHash, CenRow)>,
}

/// Select from `pool` the bodies a block on `parent` lists under
/// `rule_set`, within `budget` weight (module docs). A candidate too heavy
/// for what is left is skipped, and a lighter one after it may still fit.
///
/// # Errors
///
/// The parent view's fault, or a store invariant it observed broken — not
/// a judgement about any transaction.
pub fn select<'id, V: ChainView<'id>>(
    pool: &Pool,
    parent: &V,
    rule_set: &RuleSet,
    budget: u64,
) -> Result<Selected, Fault<V::Fault>> {
    let mut candidates: Vec<(&TxHash, &crate::pool::Held)> = pool
        .held()
        .iter()
        .filter(|(_, held)| shown(&held.record))
        .collect();
    // Most fee per weight first: `a.fee / a.weight > b.fee / b.weight` as
    // `a.fee · b.weight > b.fee · a.weight`, exact in u128.
    candidates.sort_by(|(ta, a), (tb, b)| {
        let lhs = u128::from(a.fee.to_raw()) * u128::from(b.weight);
        let rhs = u128::from(b.fee.to_raw()) * u128::from(a.weight);
        rhs.cmp(&lhs)
            .then(a.record.received.cmp(&b.record.received))
            .then(ta.cmp(tb))
    });

    let mut selected = Selected::default();
    let mut spent = KeyImages::default();
    let mut archival = BlockArchivalKeys::default();
    for (txid, held) in candidates {
        let weight = held.weight;
        if selected.weight.saturating_add(weight) > budget {
            continue;
        }
        let anchor = match held.record.standing {
            Standing::Admitted => held.proven,
            Standing::Kept { .. } => continue,
        };
        let view = PoolView::new(parent, &spent);
        match tx_against(
            &held.tx,
            TxSlot::Lone,
            &view,
            rule_set,
            anchor,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(_)) => {
                if let Err(row) = archival.add(&held.tx) {
                    selected.conflicted.push((*txid, row));
                    continue;
                }
                spent.insert(*txid, key_images_of(&held.tx));
                selected.weight += weight;
                selected.fees = selected.fees.saturating_add(held.fee.to_raw());
                selected.transactions.push((*txid, held.tx.clone()));
            }
            Ok(Err(refused)) => selected.refused.push((*txid, refused)),
            Err(Fault::Stale(_)) => selected.stale.push(*txid),
            Err(fault) => return Err(fault),
        }
    }
    Ok(selected)
}
