// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Template selection from the pool (DRS-E5 PR-b b6; `fill_block_template`'s
//! successor): which held transactions a block built on `parent` lists,
//! as a pure function of the pool, the parent's chain and a weight budget.
//!
//! Candidates are what the node shows ([`shown`](crate::shown): public — a
//! stem-phase transaction is never in a template), most fee per unit of
//! weight first (ties: the earliest held, then
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
//! [`select`] and [`select_admitting`] borrow the pool. [`select_shown`]
//! runs the same scan over a [`ShownBody`] snapshot, so a caller can drop
//! the pool lock before `tx_against`. Both entry points share one ordering
//! and one judgement.
//!
//! The coinbase, the header and the section budget are the template
//! builder's (`shekyl-block-template`); this selects the listed bodies.

use shekyl_chain_rules::{
    tx_against, BlockArchivalKeys, CenRow, ChainView, Fault, FormAttempt, InvalidBlock, RuleSet,
    StatelessPass, TxSlot, VerifiedReference,
};
use shekyl_chain_store::pool::ReceivedHour;
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

use crate::pool::{key_images_of, Pool};
use crate::rate::{AdmissionRank, FeeRate};
use crate::relay::shown;
use crate::view::{KeyImages, PoolView};

/// A body the selection listed, with the weight and fee it was judged at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedTx {
    /// The transaction's hash.
    pub id: TxHash,
    /// The body the block lists.
    pub tx: Transaction,
    /// The weight the admission was offered.
    pub weight: u64,
    /// The fee the admission was offered.
    pub fee: AtomicUnits,
}

/// What [`select`] chose, and what it could not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selected {
    /// The listed bodies, in the order the block lists them.
    pub transactions: Vec<ListedTx>,
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
    /// Candidates valid against the parent that the producer's admission
    /// declined ([`select_admitting`]): not listed, not evicted, and the
    /// next candidate is tried.
    pub declined: Vec<TxHash>,
}

/// One shown pool entry, owned so [`select_shown`] runs after the pool
/// lock is dropped. The rank is the one [`select`] would have computed
/// from the same weight, fee and receive time.
#[derive(Clone, Debug)]
pub struct ShownBody {
    id: TxHash,
    tx: Transaction,
    weight: u64,
    fee: AtomicUnits,
    received: ReceivedHour,
    pass: Option<StatelessPass>,
}

impl Pool {
    /// The entries the node shows, owned so a caller can drop the pool
    /// lock before [`select_shown`] verifies them.
    #[must_use]
    pub fn shown_bodies(&self) -> Vec<ShownBody> {
        self.held()
            .iter()
            .filter(|(_, held)| shown(&held.record))
            .map(|(id, held)| ShownBody {
                id: *id,
                tx: held.tx.clone(),
                weight: held.weight,
                fee: held.fee,
                received: held.record.received,
                pass: held.pass,
            })
            .collect()
    }
}

/// One candidate of the shared scan, borrowed from the pool or from a
/// [`ShownBody`] snapshot.
struct Candidate<'a> {
    id: TxHash,
    tx: &'a Transaction,
    weight: u64,
    fee: AtomicUnits,
    rank: AdmissionRank,
    anchor: Option<VerifiedReference>,
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
    select_admitting(pool, parent, rule_set, budget, |_, _| true)
}

/// [`select`], with the producer's admission asked of each candidate the
/// parent admits, in this order: `admit(weight, fee)` is the reward-aware
/// fill (`shekyl_block_template::Fill::admit`, DRS-X PR 3b). A candidate
/// it declines is not listed, its key images do not enter the block's
/// spent set, and the next candidate is tried. `budget` still bounds the
/// listing's weight.
///
/// # Errors
///
/// As [`select`].
pub fn select_admitting<'id, V: ChainView<'id>>(
    pool: &Pool,
    parent: &V,
    rule_set: &RuleSet,
    budget: u64,
    admit: impl FnMut(u64, u64) -> bool,
) -> Result<Selected, Fault<V::Fault>> {
    let candidates = pool
        .held()
        .iter()
        .filter(|(_, held)| shown(&held.record))
        .map(|(id, held)| Candidate {
            id: *id,
            tx: &held.tx,
            weight: held.weight,
            fee: held.fee,
            rank: held.rank(*id),
            anchor: held.pass.and_then(|pass| pass.proven()),
        })
        .collect();
    choose(candidates, parent, rule_set, budget, admit)
}

/// [`select_admitting`] over a [`Pool::shown_bodies`] snapshot. The pool
/// lock is not taken here.
///
/// # Errors
///
/// As [`select`].
pub fn select_shown<'id, V: ChainView<'id>>(
    shown_bodies: &[ShownBody],
    parent: &V,
    rule_set: &RuleSet,
    budget: u64,
    admit: impl FnMut(u64, u64) -> bool,
) -> Result<Selected, Fault<V::Fault>> {
    let candidates = shown_bodies
        .iter()
        .map(|body| Candidate {
            id: body.id,
            tx: &body.tx,
            weight: body.weight,
            fee: body.fee,
            rank: AdmissionRank::new(
                FeeRate::new(body.fee.to_raw(), body.weight),
                body.received,
                body.id,
            ),
            anchor: body.pass.and_then(|pass| pass.proven()),
        })
        .collect();
    choose(candidates, parent, rule_set, budget, admit)
}

/// The one scan both entry points run.
fn choose<'id, V: ChainView<'id>>(
    mut candidates: Vec<Candidate<'_>>,
    parent: &V,
    rule_set: &RuleSet,
    budget: u64,
    mut admit: impl FnMut(u64, u64) -> bool,
) -> Result<Selected, Fault<V::Fault>> {
    // Richest per weight first, then the earliest held, then the lesser
    // hash — the template half of the order eviction shares (`AdmissionRank`).
    candidates.sort_by(|left, right| left.rank.template(right.rank));

    let mut selected = Selected::default();
    let mut spent = KeyImages::default();
    let mut archival = BlockArchivalKeys::default();
    for candidate in candidates {
        let weight = candidate.weight;
        if selected.weight.saturating_add(weight) > budget {
            continue;
        }
        let view = PoolView::new(parent, &spent);
        match tx_against(
            candidate.tx,
            TxSlot::Lone,
            &view,
            rule_set,
            candidate.anchor,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(_)) => {
                // Added to a copy first: a body the admission declines must
                // leave the block's archival keys as they were.
                let mut listed = archival.clone();
                if let Err(row) = listed.add(candidate.tx) {
                    selected.conflicted.push((candidate.id, row));
                    continue;
                }
                if !admit(weight, candidate.fee.to_raw()) {
                    selected.declined.push(candidate.id);
                    continue;
                }
                archival = listed;
                spent.insert(candidate.id, key_images_of(candidate.tx));
                selected.weight += weight;
                selected.fees = selected.fees.saturating_add(candidate.fee.to_raw());
                selected.transactions.push(ListedTx {
                    id: candidate.id,
                    tx: candidate.tx.clone(),
                    weight,
                    fee: candidate.fee,
                });
            }
            Ok(Err(refused)) => selected.refused.push((candidate.id, refused)),
            Err(Fault::Stale(_)) => selected.stale.push(candidate.id),
            Err(fault) => return Err(fault),
        }
    }
    Ok(selected)
}
