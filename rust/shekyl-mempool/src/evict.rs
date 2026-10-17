// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10: how much the pool holds, and when a held transaction leaves it
//! without a block taking it (DRS-E5 PR-b b4; the review of #1102, S4, B3).
//!
//! # The limits derive from the chain
//!
//! [`Limits::at`] reads them off the chain at its tip; none is a constant
//! of the pool's own:
//!
//! - **The admitted cap** is `REFERENCE_BLOCK_MAX_AGE` blocks at the block
//!   weight limit in force: the most the chain could mine before every
//!   admitted entry's reference has left CEN-I11's window, after which the
//!   reconcile removes it. A pool holding more holds what can never be
//!   mined.
//! - **The kept lifetime** is the reorg cap, in blocks past the return: a
//!   kept entry's only way back is a switch back, and none reaches further.
//! - **The kept cap** is the reorg cap at the block weight limit: the most
//!   one switch's returns can weigh.
//!
//! An admitted entry has no lifetime of its own: its reference leaves
//! CEN-I11's window `REFERENCE_BLOCK_MAX_AGE` blocks after the block it
//! names, and the reconcile removes it on that refusal (S4) — sooner than
//! the C++ timer (three days, C2-R2 Q11; superseded here, E5 decision log
//! 2026-10-17).
//!
//! # The bound holds at admission
//!
//! [`Pool::admit`] makes room before it inserts, in the same write: kept
//! entries leave first (oldest return first — a kept entry's fee is not
//! one the pool can trust, since a reference this chain does not claim
//! leaves its proof unverified), then admitted entries paying strictly less
//! per unit of weight than the candidate (cheapest first). A candidate the
//! pool cannot make room for is refused before the door's crypto runs
//! ([`Admission::PoolFull`](crate::Admission::PoolFull)) — a rising minimum,
//! so a full pool is no free relay for a sender looping transactions just
//! above the floor. [`Pool::evict`] applies the same order when the limits
//! shrink under the pool.

use std::collections::BTreeSet;

use shekyl_chain_rules::{
    effective_median_at, ChainView, Fault, RuleSet, Tip, REFERENCE_BLOCK_MAX_AGE,
};
use shekyl_chain_store::pool::Standing;
use shekyl_chain_store::store::StoreError;
use shekyl_types::{BlockCount, BlockHeight, TxHash};

use crate::pool::{Held, Pool};

/// CEN-M10's limits (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How long a kept entry is held, in blocks past its return.
    pub kept_for: BlockCount,
    /// The total weight the pool holds, admitted and kept.
    pub max_weight: u64,
    /// The weight the pool holds of kept entries.
    pub kept_max_weight: u64,
}

impl Limits {
    /// The limits at the tip of `chain`, under `rule_set` (module docs).
    ///
    /// # Errors
    ///
    /// The view's fault, or a weight window it cannot answer.
    pub fn at<'id, V: ChainView<'id>>(
        chain: &V,
        rule_set: &RuleSet,
    ) -> Result<Self, Fault<V::Fault>> {
        let connecting = Tip::connecting_height(chain.tip().map_err(Fault::View)?.as_ref());
        let block = effective_median_at(chain, connecting)?.limit().to_raw();
        let cap = rule_set.reorg_cap();
        Ok(Self {
            kept_for: cap,
            max_weight: REFERENCE_BLOCK_MAX_AGE.to_raw().saturating_mul(block),
            kept_max_weight: cap.to_raw().saturating_mul(block),
        })
    }
}

/// Why CEN-M10 evicted an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evicted {
    /// The template's `tx_against` refused it against the parent.
    Refused,
    /// A kept entry past its blocks.
    KeptAged,
    /// The pool was over a weight cap (module docs: kept first, then the
    /// cheapest admitted).
    OverWeight,
}

/// `a` pays less per unit of weight than `b`, exactly: `a.fee / a.weight <
/// b.fee / b.weight` as `a.fee · b.weight < b.fee · a.weight` in u128.
fn cheaper(a: (u64, u64), b: (u64, u64)) -> bool {
    u128::from(a.0) * u128::from(b.1) < u128::from(b.0) * u128::from(a.1)
}

impl Pool {
    /// The entries to evict, in order, for `weight` more to fit — kept
    /// first (oldest return first), then admitted entries cheaper per
    /// weight than `rate` (`(fee, weight)`; `None` for a kept candidate,
    /// which displaces no admitted entry). `None` when no such set frees
    /// enough. `kept` says the candidate is kept, which also binds the
    /// kept cap.
    pub(crate) fn room_for(
        &self,
        weight: u64,
        rate: Option<(u64, u64)>,
        kept: bool,
    ) -> Option<Vec<TxHash>> {
        let limits = self.limits();
        let (mut total, mut kept_total) = (0_u128, 0_u128);
        for held in self.held().values() {
            total += u128::from(held.weight);
            if matches!(held.record.standing, Standing::Kept { .. }) {
                kept_total += u128::from(held.weight);
            }
        }
        let weight = u128::from(weight);
        let mut over = (total + weight).saturating_sub(u128::from(limits.max_weight));
        let mut kept_over = if kept {
            (kept_total + weight).saturating_sub(u128::from(limits.kept_max_weight))
        } else {
            0
        };
        if over == 0 && kept_over == 0 {
            return Some(Vec::new());
        }
        let mut victims = Vec::new();
        for (txid, held) in self.kept_oldest_first() {
            if over == 0 && kept_over == 0 {
                break;
            }
            victims.push(txid);
            over = over.saturating_sub(u128::from(held.weight));
            kept_over = kept_over.saturating_sub(u128::from(held.weight));
        }
        if kept_over > 0 {
            return None;
        }
        if over > 0 {
            let rate = rate?;
            for (txid, held) in self.admitted_cheapest_first() {
                if over == 0 {
                    break;
                }
                if !cheaper((held.fee.to_raw(), held.weight), rate) {
                    return None;
                }
                victims.push(txid);
                over = over.saturating_sub(u128::from(held.weight));
            }
        }
        (over == 0).then_some(victims)
    }

    /// Kept entries, the oldest return first, then by hash.
    fn kept_oldest_first(&self) -> Vec<(TxHash, &Held)> {
        let mut kept: Vec<(BlockHeight, TxHash, &Held)> = self
            .held()
            .iter()
            .filter_map(|(txid, held)| match held.record.standing {
                Standing::Kept { returned_at } => Some((returned_at, *txid, held)),
                Standing::Admitted => None,
            })
            .collect();
        kept.sort_by_key(|(at, txid, _)| (*at, *txid));
        kept.into_iter()
            .map(|(_, txid, held)| (txid, held))
            .collect()
    }

    /// Admitted entries, the least fee per weight first (ties: the newest
    /// first, then by hash, so the order is total).
    fn admitted_cheapest_first(&self) -> Vec<(TxHash, &Held)> {
        let mut admitted: Vec<(TxHash, &Held)> = self
            .held()
            .iter()
            .filter(|(_, held)| held.record.standing == Standing::Admitted)
            .map(|(txid, held)| (*txid, held))
            .collect();
        admitted.sort_by(|(ta, a), (tb, b)| {
            let lhs = u128::from(a.fee.to_raw()) * u128::from(b.weight);
            let rhs = u128::from(b.fee.to_raw()) * u128::from(a.weight);
            lhs.cmp(&rhs)
                .then(b.record.received.cmp(&a.record.received))
                .then(ta.cmp(tb))
        });
        admitted
    }

    /// Apply CEN-M10 with the chain at `tip` (module docs), `refused` being
    /// the admitted entries the last template selection refused against its
    /// parent. Writes every removal to the file in one batch (P3), then
    /// drops the entries and their key images from the index.
    ///
    /// # Errors
    ///
    /// The pool file's; nothing is dropped from the index unless the file
    /// dropped it.
    pub fn evict(
        &mut self,
        tip: BlockHeight,
        refused: &[TxHash],
    ) -> Result<Vec<(TxHash, Evicted)>, StoreError> {
        let limits = self.limits();
        let mut evicted: Vec<(TxHash, Evicted)> = Vec::new();
        let mut gone: BTreeSet<TxHash> = BTreeSet::new();
        for txid in refused {
            if self
                .held()
                .get(txid)
                .is_some_and(|held| held.record.standing == Standing::Admitted)
                && gone.insert(*txid)
            {
                evicted.push((*txid, Evicted::Refused));
            }
        }
        for (txid, held) in self.held() {
            if let Standing::Kept { returned_at } = held.record.standing {
                if tip.to_raw().saturating_sub(returned_at.to_raw()) >= limits.kept_for.to_raw()
                    && gone.insert(*txid)
                {
                    evicted.push((*txid, Evicted::KeptAged));
                }
            }
        }
        // The weight caps over what survives: kept first, oldest first, then
        // the cheapest admitted.
        let survives = |txid: &TxHash| !gone.contains(txid);
        let weigh = |entries: &[(TxHash, &Held)]| -> u128 {
            entries
                .iter()
                .filter(|(txid, _)| survives(txid))
                .map(|(_, held)| u128::from(held.weight))
                .sum()
        };
        let kept = self.kept_oldest_first();
        let admitted = self.admitted_cheapest_first();
        let mut kept_total = weigh(&kept);
        let mut total = kept_total + weigh(&admitted);
        let mut over_weight = Vec::new();
        for (txid, held) in kept.iter().filter(|(txid, _)| survives(txid)) {
            if total <= u128::from(limits.max_weight)
                && kept_total <= u128::from(limits.kept_max_weight)
            {
                break;
            }
            total -= u128::from(held.weight);
            kept_total -= u128::from(held.weight);
            over_weight.push(*txid);
        }
        for (txid, held) in admitted.iter().filter(|(txid, _)| survives(txid)) {
            if total <= u128::from(limits.max_weight) {
                break;
            }
            total -= u128::from(held.weight);
            over_weight.push(*txid);
        }
        evicted.extend(
            over_weight
                .into_iter()
                .map(|txid| (txid, Evicted::OverWeight)),
        );
        if !evicted.is_empty() {
            self.store()
                .write(|batch| evicted.iter().try_for_each(|(txid, _)| batch.remove(txid)))?;
            for (txid, _) in &evicted {
                self.drop_held(txid);
            }
        }
        Ok(evicted)
    }
}

#[cfg(test)]
#[path = "evict_tests.rs"]
mod evict_tests;
