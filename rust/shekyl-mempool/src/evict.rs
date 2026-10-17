// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10: when a held transaction leaves the pool without a block taking
//! it (DRS-E5 PR-b b4).
//!
//! Four reasons, in the order [`Pool::evict`] applies them:
//!
//! 1. **Refused by the chain at template time** — an admitted entry the
//!    template selection's `tx_against` refused against the template's
//!    parent (b6): its reference aged out of CEN-I11's window, or the chain
//!    spent its image. It can never be mined on this chain.
//! 2. **Aged** — an admitted entry held longer than
//!    [`Limits::admitted_lifetime`].
//! 3. **Kept and aged** — a kept entry (CEN-K10) held longer than
//!    [`Limits::kept_lifetime`], the longer window a returned transaction
//!    gets for a reorg to make it valid again.
//! 4. **Over the weight cap** — while the pool's total weight exceeds
//!    [`Limits::max_weight`], the entry paying the least per unit of weight
//!    leaves first (ties: the newest first, then by hash, so the order is
//!    total).
//!
//! The three limits are the C++ pool's (`cryptonote_config.h`:
//! `CRYPTONOTE_MEMPOOL_TX_LIVETIME`, `CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME`,
//! `DEFAULT_TXPOOL_MAX_WEIGHT`), carried as given: the census records that
//! no round has ratified them as policy choices (CEN-M10, §10 R2/R7), and
//! this crate restates no reason for them. A pin holds them to the C++
//! values while both pools exist (`evict_tests.rs`).

use shekyl_chain_store::pool::{PoolRecord, Standing};
use shekyl_chain_store::store::StoreError;
use shekyl_types::{TxHash, UnixSeconds};

use crate::pool::Pool;

/// CEN-M10's three limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How long an admitted entry is held, in seconds.
    pub admitted_lifetime: u64,
    /// How long a kept entry is held, in seconds.
    pub kept_lifetime: u64,
    /// The pool's total weight cap.
    pub max_weight: u64,
}

impl Limits {
    /// The limits in force from genesis: three days, one week, 648 MB.
    pub const GENESIS: Self = Self {
        admitted_lifetime: 86_400 * 3,
        kept_lifetime: 604_800,
        max_weight: 648_000_000,
    };
}

/// Why CEN-M10 evicted an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evicted {
    /// The template's `tx_against` refused it against the parent.
    Refused,
    /// An admitted entry past its lifetime.
    Aged,
    /// A kept entry past its lifetime.
    KeptAged,
    /// The pool was over its weight cap and it paid the least per weight.
    OverWeight,
}

/// Whether `record` is past its lifetime at `now`.
fn aged(record: &PoolRecord, now: UnixSeconds, limits: &Limits) -> Option<Evicted> {
    let held_for = now.to_raw().saturating_sub(record.receive_time.to_raw());
    match record.standing {
        Standing::Admitted { .. } if held_for > limits.admitted_lifetime => Some(Evicted::Aged),
        Standing::Kept if held_for > limits.kept_lifetime => Some(Evicted::KeptAged),
        _ => None,
    }
}

impl Pool {
    /// Apply CEN-M10 at `now` (module docs), `refused` being the admitted
    /// entries the last template selection refused against its parent.
    /// Writes every removal to the file in one batch (P3), then drops the
    /// entries and their key images from the index.
    ///
    /// # Errors
    ///
    /// The pool file's; nothing is dropped from the index unless the file
    /// dropped it.
    pub fn evict(
        &mut self,
        now: UnixSeconds,
        limits: &Limits,
        refused: &[TxHash],
    ) -> Result<Vec<(TxHash, Evicted)>, StoreError> {
        let mut evicted: Vec<(TxHash, Evicted)> = Vec::new();
        for txid in refused {
            if self
                .held()
                .get(txid)
                .is_some_and(|held| matches!(held.record.standing, Standing::Admitted { .. }))
            {
                evicted.push((*txid, Evicted::Refused));
            }
        }
        for (txid, held) in self.held() {
            if evicted.iter().any(|(gone, _)| gone == txid) {
                continue;
            }
            if let Some(why) = aged(&held.record, now, limits) {
                evicted.push((*txid, why));
            }
        }

        // The weight cap over what survives, cheapest per weight first.
        let mut survivors: Vec<(TxHash, PoolRecord)> = self
            .held()
            .iter()
            .filter(|(txid, _)| !evicted.iter().any(|(gone, _)| gone == *txid))
            .map(|(txid, held)| (*txid, held.record))
            .collect();
        let mut total: u128 = survivors.iter().map(|(_, r)| u128::from(r.weight)).sum();
        // Ascending fee per weight: `a.fee / a.weight < b.fee / b.weight`
        // compared as `a.fee · b.weight < b.fee · a.weight`, exact in u128;
        // then the newest first, then the hash.
        survivors.sort_by(|(ta, a), (tb, b)| {
            let lhs = u128::from(a.fee.to_raw()) * u128::from(b.weight);
            let rhs = u128::from(b.fee.to_raw()) * u128::from(a.weight);
            lhs.cmp(&rhs)
                .then(b.receive_time.cmp(&a.receive_time))
                .then(ta.cmp(tb))
        });
        for (txid, record) in survivors {
            if total <= u128::from(limits.max_weight) {
                break;
            }
            total -= u128::from(record.weight);
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
