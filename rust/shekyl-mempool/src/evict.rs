// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10: how much the pool holds, and when a held transaction leaves it
//! without a block taking it (DRS-E5 PR-b b4; the review of #1102, S4, B3;
//! the rulings of 2026-10-17).
//!
//! # The limit derives from the chain
//!
//! [`Limits::at`] reads it off the chain at its tip; it is not a constant
//! of the pool's own. The pool holds `REFERENCE_BLOCK_MAX_AGE` blocks at
//! the block weight limit in force — the hard limit, twice the penalty-free
//! zone — which is the most the chain could mine before every held entry's
//! reference has left CEN-I11's window, after which the reconcile removes
//! it. A pool holding more holds what can never be mined. At genesis that
//! is 100 × 600 000 bytes, 60 MB.
//!
//! This replaces C2-R2 Q11 (signed 2026-09-06; superseded for the Rust
//! pool by ruling, 2026-10-17), and so does its basis. Q11 derived its cap
//! from the pool's three-day lifetime and the **penalty-free** block size:
//! 2 160 blocks × 300 000 bytes, 648 MB. The lifetime is gone (below), so
//! its horizon is the reference window instead, and the block size is the
//! **hard limit**, because a block may be that heavy and the window is the
//! most the chain could mine in it.
//!
//! An entry has no lifetime of its own: its reference leaves CEN-I11's
//! window `REFERENCE_BLOCK_MAX_AGE` blocks after the block it names, and
//! the reconcile removes it on that refusal (S4) — sooner than the C++
//! three-day timer, which this replaces. Nor is there a reorg retention
//! (CEN-K10, deleted 2026-10-17): a transaction a popped block returns is
//! judged like any other, and its body stays in the chain store for any
//! switch back (`block.rs`).
//!
//! # The bound holds at admission
//!
//! [`Pool::admit`] makes room before it inserts, in the same write: the
//! entries paying strictly less per unit of weight than the candidate
//! leave, the cheapest first. A candidate the pool cannot make room for is
//! refused before the door's crypto runs
//! ([`Admission::PoolFull`](crate::Admission::PoolFull)) — a rising minimum,
//! so a full pool is no free relay for a sender looping transactions just
//! above the floor. [`Pool::evict`] applies the same order when the limit
//! shrinks under the pool.

use std::collections::BTreeSet;

use shekyl_chain_rules::{effective_median_at, ChainView, Fault, Tip, REFERENCE_BLOCK_MAX_AGE};
use shekyl_chain_store::store::StoreError;
use shekyl_types::TxHash;

use crate::pool::{Held, Pool};
use crate::rate::FeeRate;

/// CEN-M10's limit (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The total weight the pool holds.
    pub max_weight: u64,
}

impl Limits {
    /// The limit at the tip of `chain` (module docs).
    ///
    /// # Errors
    ///
    /// The view's fault, or a weight window it cannot answer.
    pub fn at<'id, V: ChainView<'id>>(chain: &V) -> Result<Self, Fault<V::Fault>> {
        let connecting = Tip::connecting_height(chain.tip().map_err(Fault::View)?.as_ref());
        let block = effective_median_at(chain, connecting)?.limit().to_raw();
        Ok(Self {
            max_weight: REFERENCE_BLOCK_MAX_AGE.to_raw().saturating_mul(block),
        })
    }
}

/// Why CEN-M10 evicted an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evicted {
    /// The template's `tx_against` refused it against the parent.
    Refused,
    /// The pool was over its weight limit (module docs: the cheapest per
    /// weight first).
    OverWeight,
}

impl Pool {
    /// The entries to evict, in order, for `weight` more to fit: entries
    /// paying strictly less per weight than `candidate`, the cheapest
    /// first ([`FeeRate`], [`crate::rate::AdmissionRank::eviction`]).
    /// `None` when no such set frees enough. An equal rate does not leave.
    pub(crate) fn room_for(&self, weight: u64, candidate: FeeRate) -> Option<Vec<TxHash>> {
        let total: u128 = self
            .held()
            .values()
            .map(|held| u128::from(held.weight))
            .sum();
        let mut over =
            (total + u128::from(weight)).saturating_sub(u128::from(self.limits().max_weight));
        let mut victims = Vec::new();
        for (txid, held) in self.cheapest_first() {
            if over == 0 {
                break;
            }
            if held.rate().cmp_rate(candidate) != core::cmp::Ordering::Less {
                return None;
            }
            victims.push(txid);
            over = over.saturating_sub(u128::from(held.weight));
        }
        (over == 0).then_some(victims)
    }

    /// Every entry, the least fee per weight first (ties: the newest first,
    /// then by hash, so the order is total).
    fn cheapest_first(&self) -> Vec<(TxHash, &Held)> {
        let mut held: Vec<(TxHash, &Held)> = self
            .held()
            .iter()
            .map(|(txid, held)| (*txid, held))
            .collect();
        held.sort_by(|(ta, a), (tb, b)| a.rank(*ta).eviction(b.rank(*tb)));
        held
    }

    /// Apply CEN-M10, `refused` being the entries the last template
    /// selection refused against its parent: those leave, then the
    /// cheapest per weight until the pool is within its limit. Writes every
    /// removal to the file in one batch (P3), then drops the entries and
    /// their key images from the index.
    ///
    /// # Errors
    ///
    /// The pool file's; nothing is dropped from the index unless the file
    /// dropped it.
    pub fn evict(&mut self, refused: &[TxHash]) -> Result<Vec<(TxHash, Evicted)>, StoreError> {
        let mut evicted: Vec<(TxHash, Evicted)> = Vec::new();
        let mut gone: BTreeSet<TxHash> = BTreeSet::new();
        for txid in refused {
            if self.held().contains_key(txid) && gone.insert(*txid) {
                evicted.push((*txid, Evicted::Refused));
            }
        }
        let limit = u128::from(self.limits().max_weight);
        let survivors: Vec<(TxHash, &Held)> = self
            .cheapest_first()
            .into_iter()
            .filter(|(txid, _)| !gone.contains(txid))
            .collect();
        let mut total: u128 = survivors
            .iter()
            .map(|(_, held)| u128::from(held.weight))
            .sum();
        let mut over_weight = Vec::new();
        for (txid, held) in survivors {
            if total <= limit {
                break;
            }
            total -= u128::from(held.weight);
            over_weight.push(txid);
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
