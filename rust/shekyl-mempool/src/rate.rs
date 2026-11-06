// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee per weight, one comparison for every reader of it (CEN-M10).
//!
//! The rate is the cross-multiply `fee_a · weight_b ? fee_b · weight_a` in
//! `u128`. A zero weight stays in that arithmetic: the other side is multiplied
//! by zero, which is what eviction and template selection already compared.
//!
//! Two orders share the rate and the lesser-hash tie. They differ on when the
//! pool first held the transaction, and that difference is the policy:
//! eviction removes the cheapest, then the newest; a template lists the
//! richest, then the earliest. The hash runs the same way in both, so neither
//! order is the reverse of the other.

use shekyl_chain_store::pool::ReceivedHour;
use shekyl_types::TxHash;

/// A transaction's fee and weight, the pair [`FeeRate::cmp_rate`] compares.
/// Neither field is a rate on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FeeRate {
    fee: u64,
    weight: u64,
}

impl FeeRate {
    /// `fee` atomic units over `weight`.
    pub(crate) const fn new(fee: u64, weight: u64) -> Self {
        Self { fee, weight }
    }

    /// How this fee per weight compares with `other`'s.
    pub(crate) fn cmp_rate(self, other: Self) -> core::cmp::Ordering {
        let left = u128::from(self.fee) * u128::from(other.weight);
        let right = u128::from(other.fee) * u128::from(self.weight);
        left.cmp(&right)
    }
}

/// One candidate in the shared order: its rate, when the pool first held it,
/// and its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionRank {
    rate: FeeRate,
    received: ReceivedHour,
    txid: TxHash,
}

impl AdmissionRank {
    /// `rate` for the entry received at `received`, identified by `txid`.
    pub(crate) const fn new(rate: FeeRate, received: ReceivedHour, txid: TxHash) -> Self {
        Self {
            rate,
            received,
            txid,
        }
    }

    /// Cheapest first, then the newest, then the lesser hash.
    pub(crate) fn eviction(self, other: Self) -> core::cmp::Ordering {
        self.finish(
            other,
            self.rate.cmp_rate(other.rate),
            other.received.cmp(&self.received),
        )
    }

    /// Richest first, then the earliest, then the lesser hash.
    pub(crate) fn template(self, other: Self) -> core::cmp::Ordering {
        self.finish(
            other,
            other.rate.cmp_rate(self.rate),
            self.received.cmp(&other.received),
        )
    }

    fn finish(
        self,
        other: Self,
        rate: core::cmp::Ordering,
        receipt: core::cmp::Ordering,
    ) -> core::cmp::Ordering {
        rate.then(receipt).then(self.txid.cmp(&other.txid))
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionRank, FeeRate};
    use shekyl_chain_store::pool::ReceivedHour;
    use shekyl_types::TxHash;

    fn rank(fee: u64, weight: u64, received: u64, byte: u8) -> AdmissionRank {
        AdmissionRank::new(
            FeeRate::new(fee, weight),
            ReceivedHour::from_raw(received),
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
}
