// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10's policy with nothing stored: fee per weight, the two orders that
//! share it, the pool's weight limit, and which entries leave to make room.
//!
//! The pool ([`crate::Pool`]) calls these, and so does the economics sim,
//! which models the pool without a store. This module builds without the
//! `pool` feature, so a caller that has no store does not take one.
//!
//! The rate is the cross-multiply `fee_a · weight_b ? fee_b · weight_a` in
//! `u128`. A zero weight stays in that arithmetic: the other side is multiplied
//! by zero, which is what eviction and template selection already compared.
//!
//! Two orders share the rate and the lesser-hash tie. They differ on when the
//! pool first held the transaction, and that difference is the policy:
//! eviction removes the cheapest, then the newest; a template lists the
//! richest, then the earliest. The hash runs the same way in both, so neither
//! order is the reverse of the other. [`eviction_order`] and
//! [`template_order`] are the two orders before the hash, for a caller whose
//! entries have no hash of their own.

use core::cmp::Ordering;

use shekyl_chain_rules::REFERENCE_BLOCK_MAX_AGE;
use shekyl_types::TxHash;

/// A transaction's fee and weight, the pair [`FeeRate::cmp_rate`] compares.
/// Neither field is a rate on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate {
    fee: u64,
    weight: u64,
}

impl FeeRate {
    /// `fee` atomic units over `weight`.
    #[must_use]
    pub const fn new(fee: u64, weight: u64) -> Self {
        Self { fee, weight }
    }

    /// How this fee per weight compares with `other`'s.
    #[must_use]
    pub fn cmp_rate(self, other: Self) -> Ordering {
        let left = u128::from(self.fee) * u128::from(other.weight);
        let right = u128::from(other.fee) * u128::from(self.weight);
        left.cmp(&right)
    }
}

/// Eviction's order before the hash: the cheapest per weight first, then the
/// one the pool held later. `received` is any key that orders by when the
/// pool first held the entry; the pool's is the hour (`ReceivedHour`).
#[must_use]
pub fn eviction_order<R: Ord + Copy>(a: (FeeRate, R), b: (FeeRate, R)) -> Ordering {
    a.0.cmp_rate(b.0).then(b.1.cmp(&a.1))
}

/// A template's order before the hash: the richest per weight first, then
/// the one the pool held earlier. `received` as in [`eviction_order`].
#[must_use]
pub fn template_order<R: Ord + Copy>(a: (FeeRate, R), b: (FeeRate, R)) -> Ordering {
    b.0.cmp_rate(a.0).then(a.1.cmp(&b.1))
}

/// One candidate in the shared order: its rate, when the pool first held it,
/// and its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionRank<R> {
    rate: FeeRate,
    received: R,
    txid: TxHash,
}

impl<R: Ord + Copy> AdmissionRank<R> {
    /// `rate` for the entry received at `received`, identified by `txid`.
    pub const fn new(rate: FeeRate, received: R, txid: TxHash) -> Self {
        Self {
            rate,
            received,
            txid,
        }
    }

    /// Cheapest first, then the newest, then the lesser hash.
    #[must_use]
    pub fn eviction(self, other: Self) -> Ordering {
        eviction_order((self.rate, self.received), (other.rate, other.received))
            .then(self.txid.cmp(&other.txid))
    }

    /// Richest first, then the earliest, then the lesser hash.
    #[must_use]
    pub fn template(self, other: Self) -> Ordering {
        template_order((self.rate, self.received), (other.rate, other.received))
            .then(self.txid.cmp(&other.txid))
    }
}

/// CEN-M10's limit (`evict.rs`'s module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The total weight the pool holds.
    pub max_weight: u64,
}

impl Limits {
    /// The limit when `block_weight_limit` is the block weight limit in
    /// force: `REFERENCE_BLOCK_MAX_AGE` blocks of it, the most the chain
    /// could mine before every held entry's reference has left CEN-I11's
    /// window.
    #[must_use]
    pub const fn of_block_limit(block_weight_limit: u64) -> Self {
        Self {
            max_weight: REFERENCE_BLOCK_MAX_AGE
                .to_raw()
                .saturating_mul(block_weight_limit),
        }
    }
}

/// The entries to evict for `weight` more to fit under `limit`, when the
/// pool holds `total` weight: entries paying strictly less per weight than
/// `candidate`, taken from `cheapest_first` (the entries as `(key, rate,
/// weight)`, in [`AdmissionRank::eviction`]'s order) until the candidate
/// fits. `None` when no such set frees enough. An equal rate does not leave.
pub fn make_room<K>(
    total: u128,
    weight: u64,
    limit: u64,
    candidate: FeeRate,
    cheapest_first: impl IntoIterator<Item = (K, FeeRate, u64)>,
) -> Option<Vec<K>> {
    let mut over = (total + u128::from(weight)).saturating_sub(u128::from(limit));
    let mut victims = Vec::new();
    for (key, rate, held_weight) in cheapest_first {
        if over == 0 {
            break;
        }
        if rate.cmp_rate(candidate) != Ordering::Less {
            return None;
        }
        victims.push(key);
        over = over.saturating_sub(u128::from(held_weight));
    }
    (over == 0).then_some(victims)
}

/// The entries to evict to bring the pool within `limit`: from
/// `cheapest_first` (the survivors as `(key, weight)`, in
/// [`AdmissionRank::eviction`]'s order), the cheapest per weight until the
/// total is within the limit, passing over the entries `listed` names (a
/// posted template's bodies). The listed entries count toward the total and
/// are never chosen.
pub fn trim_to<K>(
    limit: u64,
    cheapest_first: impl IntoIterator<Item = (K, u64)> + Clone,
    listed: impl Fn(&K) -> bool,
) -> Vec<K> {
    let limit = u128::from(limit);
    let mut total: u128 = cheapest_first
        .clone()
        .into_iter()
        .map(|(_, weight)| u128::from(weight))
        .sum();
    let mut over_weight = Vec::new();
    for (key, weight) in cheapest_first {
        if total <= limit {
            break;
        }
        if listed(&key) {
            continue;
        }
        total -= u128::from(weight);
        over_weight.push(key);
    }
    over_weight
}

#[cfg(test)]
mod tests {
    use super::{make_room, trim_to, AdmissionRank, FeeRate, Limits};
    use shekyl_types::TxHash;

    fn rank(fee: u64, weight: u64, received: u64, byte: u8) -> AdmissionRank<u64> {
        AdmissionRank::new(
            FeeRate::new(fee, weight),
            received,
            TxHash::from_bytes([byte; 32]),
        )
    }

    /// 2/5 against 3/7 is 14 against 15. Integer division ties them both at 0.
    #[test]
    fn the_cross_multiply_separates_rates_integer_division_ties() {
        let cheap = FeeRate::new(2, 5);
        let rich = FeeRate::new(3, 7);
        assert_eq!(cheap.cmp_rate(rich), core::cmp::Ordering::Less);
        assert_eq!(rich.cmp_rate(cheap), core::cmp::Ordering::Greater);
        assert_eq!(2u64 / 5, 3u64 / 7);
    }

    /// Equal rates: eviction takes the newer first, a template the earlier.
    #[test]
    fn equal_rates_evict_the_newer_and_template_the_earlier() {
        let older = rank(1, 2, 1, 0x20);
        let newer = rank(2, 4, 9, 0x20);
        assert_eq!(older.rate.cmp_rate(newer.rate), core::cmp::Ordering::Equal);
        assert_eq!(newer.eviction(older), core::cmp::Ordering::Less);
        assert_eq!(newer.template(older), core::cmp::Ordering::Greater);
    }

    /// Equal rate and receipt: the lesser hash is earlier in both orders.
    #[test]
    fn equal_rate_and_receipt_keep_the_lesser_hash_first_in_both_orders() {
        let lesser = rank(4, 8, 3, 0x01);
        let greater = rank(4, 8, 3, 0x02);
        assert_eq!(lesser.eviction(greater), core::cmp::Ordering::Less);
        assert_eq!(lesser.template(greater), core::cmp::Ordering::Less);
    }

    /// The limit is `REFERENCE_BLOCK_MAX_AGE` blocks at the block limit:
    /// 60 MB at genesis's 600 000-byte limit.
    #[test]
    fn the_limit_is_the_reference_window_of_block_limits() {
        assert_eq!(Limits::of_block_limit(600_000).max_weight, 60_000_000);
    }

    /// Room comes from strictly cheaper entries only, the cheapest first,
    /// and is refused when they do not free enough.
    #[test]
    fn room_is_made_from_strictly_cheaper_entries_or_not_at_all() {
        let held = [(1, FeeRate::new(1, 10), 10), (2, FeeRate::new(5, 10), 10)];
        // Fits without a victim.
        assert_eq!(
            make_room(20, 10, 30, FeeRate::new(9, 10), held),
            Some(vec![])
        );
        // One victim frees enough.
        assert_eq!(
            make_room(20, 10, 20, FeeRate::new(9, 10), held),
            Some(vec![1])
        );
        // An equal rate does not leave.
        assert_eq!(make_room(20, 10, 20, FeeRate::new(1, 10), held), None);
        // Both cheaper, still not enough.
        assert_eq!(make_room(20, 30, 20, FeeRate::new(9, 10), held), None);
    }

    /// Trimming passes over the listed entries and stops once within the
    /// limit.
    #[test]
    fn trimming_passes_over_the_listed_and_stops_within_the_limit() {
        let held = [(1, 10u64), (2, 10), (3, 10)];
        assert_eq!(trim_to(30, held, |_| false), Vec::<i32>::new());
        assert_eq!(trim_to(20, held, |_| false), vec![1]);
        assert_eq!(trim_to(20, held, |key| *key == 1), vec![2]);
        assert_eq!(trim_to(0, held, |key| *key == 2), vec![1, 3]);
    }
}
