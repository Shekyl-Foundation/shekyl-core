// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10: when a held transaction leaves the pool without a block taking
//! it (DRS-E5 PR-b b4; the review of #1102, S4 and B3).
//!
//! Three reasons, in the order [`Pool::evict`] applies them:
//!
//! 1. **Refused by the chain at template time** — an admitted entry the
//!    template selection's `tx_against` refused against the template's
//!    parent (b6): its reference aged out of CEN-I11's window, or the chain
//!    spent its image. It can never be mined on this chain.
//! 2. **Kept and aged** — a kept entry (CEN-K10) once the tip is
//!    [`Limits::kept_for`] blocks past the height it was returned at. Its
//!    only way back is a switch back, and none reaches further than the
//!    reorg cap.
//! 3. **Over the weight cap** — while the pool's total weight exceeds
//!    [`Limits::max_weight`], the entry paying the least per unit of weight
//!    leaves first (ties: the newest first, then by hash, so the order is
//!    total).
//!
//! **An admitted entry has no lifetime of its own.** Its reference ages out
//! of CEN-I11's window `REFERENCE_BLOCK_MAX_AGE` blocks after the block it
//! names, and the reconcile removes it on that refusal (S4) — sooner than
//! the C++ timer (three days).

use shekyl_chain_rules::RuleSet;
use shekyl_chain_store::pool::Standing;
use shekyl_chain_store::store::StoreError;
use shekyl_types::{BlockCount, BlockHeight, TxHash};
use shekyl_units::AtomicUnits;

use crate::pool::Pool;

/// CEN-M10's limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How long a kept entry is held, in blocks past its return.
    pub kept_for: BlockCount,
    /// The pool's total weight cap.
    pub max_weight: u64,
}

impl Limits {
    /// The limits in force from genesis: a kept entry for the genesis reorg
    /// cap; 648 MB, the C++ pool's cap (`DEFAULT_TXPOOL_MAX_WEIGHT`).
    pub const GENESIS: Self = Self {
        kept_for: RuleSet::GENESIS.reorg_cap(),
        max_weight: 648_000_000,
    };
}

/// Why CEN-M10 evicted an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evicted {
    /// The template's `tx_against` refused it against the parent.
    Refused,
    /// A kept entry past its blocks.
    KeptAged,
    /// The pool was over its weight cap and it paid the least per weight.
    OverWeight,
}

impl Pool {
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
        limits: &Limits,
        refused: &[TxHash],
    ) -> Result<Vec<(TxHash, Evicted)>, StoreError> {
        let mut evicted: Vec<(TxHash, Evicted)> = Vec::new();
        for txid in refused {
            if self
                .held()
                .get(txid)
                .is_some_and(|held| held.record.standing == Standing::Admitted)
            {
                evicted.push((*txid, Evicted::Refused));
            }
        }
        for (txid, held) in self.held() {
            if evicted.iter().any(|(gone, _)| gone == txid) {
                continue;
            }
            if let Standing::Kept { returned_at } = held.record.standing {
                if tip.to_raw().saturating_sub(returned_at.to_raw()) >= limits.kept_for.to_raw() {
                    evicted.push((*txid, Evicted::KeptAged));
                }
            }
        }
        // The weight cap over what survives, cheapest per weight first.
        let mut survivors: Vec<(
            TxHash,
            u64,
            AtomicUnits,
            shekyl_chain_store::pool::ReceivedHour,
        )> = self
            .held()
            .iter()
            .filter(|(txid, _)| !evicted.iter().any(|(gone, _)| gone == *txid))
            .map(|(txid, held)| (*txid, held.weight, held.fee, held.record.received))
            .collect();
        let mut total: u128 = survivors.iter().map(|(_, w, _, _)| u128::from(*w)).sum();
        // Ascending fee per weight: `a.fee / a.weight < b.fee / b.weight`
        // compared as `a.fee · b.weight < b.fee · a.weight`, exact in u128;
        // then the newest first, then the hash.
        survivors.sort_by(|(ta, wa, fa, ra), (tb, wb, fb, rb)| {
            let lhs = u128::from(fa.to_raw()) * u128::from(*wb);
            let rhs = u128::from(fb.to_raw()) * u128::from(*wa);
            lhs.cmp(&rhs).then(rb.cmp(ra)).then(ta.cmp(tb))
        });
        for (txid, weight, _, _) in survivors {
            if total <= u128::from(limits.max_weight) {
                break;
            }
            total -= u128::from(weight);
            evicted.push((txid, Evicted::OverWeight));
        }
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
