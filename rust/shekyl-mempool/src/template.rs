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
//! The coinbase, the header and the section budget are the template
//! builder's (`shekyl-block-template`); this selects the listed bodies.

use shekyl_chain_rules::{
    tx_against, ChainView, Fault, FormAttempt, InvalidBlock, RuleSet, TxSlot,
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
        let lhs = u128::from(a.record.fee.to_raw()) * u128::from(b.record.weight);
        let rhs = u128::from(b.record.fee.to_raw()) * u128::from(a.record.weight);
        rhs.cmp(&lhs)
            .then(a.record.receive_time.cmp(&b.record.receive_time))
            .then(ta.cmp(tb))
    });

    let mut selected = Selected::default();
    let mut spent = KeyImages::default();
    for (txid, held) in candidates {
        let weight = held.record.weight;
        if selected.weight.saturating_add(weight) > budget {
            continue;
        }
        let anchor = match held.record.standing {
            Standing::Admitted { proven } => proven.map(|p| p.verified()),
            Standing::Kept => continue,
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
                spent.insert(*txid, key_images_of(&held.tx));
                selected.weight += weight;
                selected.fees = selected.fees.saturating_add(held.record.fee.to_raw());
                selected.transactions.push((*txid, held.tx.clone()));
            }
            Ok(Err(refused)) => selected.refused.push((*txid, refused)),
            Err(Fault::Stale(_)) => selected.stale.push(*txid),
            Err(fault) => return Err(fault),
        }
    }
    Ok(selected)
}
