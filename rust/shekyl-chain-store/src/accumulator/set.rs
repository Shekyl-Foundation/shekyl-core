// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Order-independent XOR fold — §6.2's set-shaped class.

use shekyl_crypto_hash::cshake256_32;

use super::domain::AccumulatorDomain;

/// XOR of per-element hashes — §6.2's **set-shaped** class.
///
/// Order-independent, so the fold does not depend on comparator order.
/// This matters concretely: `compare_hash32` orders three set-shaped
/// tables' duplicates as a little-endian 256-bit integer rather than
/// lexicographically (audit §12), and an order-independent fold is why
/// that wart never reaches a digest.
///
/// [`insert`](Self::insert) and [`remove`](Self::remove) are the **same
/// operation**. XOR is an involution, which is exactly what
/// "pop-symmetric by construction" means — and the property that makes
/// a wrong argument undetectable. Detection is checkpoint
/// reconciliation's job, not this type's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAccumulator {
    /// cSHAKE customization for this table's leaves. Per-table, so two
    /// tables holding identical bytes do not fold to the same value.
    element_domain: AccumulatorDomain,
    acc: [u8; 32],
}

impl SetAccumulator {
    /// Empty accumulator over `element_domain`.
    ///
    /// The domain is required rather than defaulted: two tables whose
    /// elements are both bare 32-byte hashes would otherwise cancel each
    /// other out across a combined digest.
    ///
    /// # Panics
    ///
    /// Panics if `element_domain` is empty.
    #[must_use]
    pub const fn new(element_domain: &'static [u8]) -> Self {
        Self {
            element_domain: AccumulatorDomain::new(element_domain),
            acc: [0u8; 32],
        }
    }

    /// Fold `element`'s canonical encoding in.
    pub fn insert(&mut self, element: &[u8]) {
        self.toggle(element);
    }

    /// Fold `element`'s canonical encoding back out.
    ///
    /// Identical to [`insert`](Self::insert). `element` must be the
    /// encoding **read back from the store**, not a caller-reconstructed
    /// value. Six set-shaped tables delete by key alone in C++; a port
    /// that folds a reconstructed argument desynchronizes silently.
    pub fn remove(&mut self, element: &[u8]) {
        self.toggle(element);
    }

    fn toggle(&mut self, element: &[u8]) {
        let leaf = cshake256_32(self.element_domain.as_bytes(), element);
        xor_in_place(&mut self.acc, &leaf);
    }

    /// Current accumulator value. All-zero for an empty table.
    #[must_use]
    pub const fn value(&self) -> [u8; 32] {
        self.acc
    }
}

fn xor_in_place(acc: &mut [u8; 32], leaf: &[u8; 32]) {
    for (dst, src) in acc.iter_mut().zip(leaf.iter()) {
        *dst ^= *src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KI: &[u8] = b"shekyl/test/spent-elem";

    fn elem(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn set_insert_then_remove_returns_to_identity() {
        let mut acc = SetAccumulator::new(KI);
        let empty = acc.value();
        acc.insert(&elem(1));
        assert_ne!(acc.value(), empty, "insert must move the accumulator");
        acc.remove(&elem(1));
        assert_eq!(acc.value(), empty, "remove must undo insert exactly");
    }

    #[test]
    fn set_pop_symmetry_holds_for_a_whole_block_of_elements() {
        let mut acc = SetAccumulator::new(KI);
        for n in 0..8 {
            acc.insert(&elem(n));
        }
        let after_connect = acc.value();
        for n in 8..16 {
            acc.insert(&elem(n));
        }
        // Pop the second block in an order unrelated to the insert order.
        for n in (8..16).rev() {
            acc.remove(&elem(n));
        }
        assert_eq!(
            acc.value(),
            after_connect,
            "pop must restore the pre-connect value"
        );
    }

    #[test]
    fn set_fold_is_order_independent() {
        let mut a = SetAccumulator::new(KI);
        let mut b = SetAccumulator::new(KI);
        for n in 0..6 {
            a.insert(&elem(n));
        }
        for n in (0..6).rev() {
            b.insert(&elem(n));
        }
        assert_eq!(a.value(), b.value(), "XOR fold must not depend on order");
    }

    #[test]
    fn set_empty_accumulator_is_all_zero() {
        assert_eq!(SetAccumulator::new(KI).value(), [0u8; 32]);
    }

    #[test]
    fn set_accumulator_reproduces_the_shipped_v0_spent_accumulator() {
        // Continuity with the full-domain oracle: the incremental form must
        // be a drop-in for digest_v0's, or DRS-E2 cannot compare the two.
        // These stay independent implementations; this test is the pin.
        use crate::digest_v0::{spent_accumulator, SPENT_ELEM_CUSTOMIZATION};
        let keys: Vec<[u8; 32]> = (0..5).map(elem).collect();
        let mut acc = SetAccumulator::new(SPENT_ELEM_CUSTOMIZATION);
        for k in &keys {
            acc.insert(k);
        }
        assert_eq!(acc.value(), spent_accumulator(&keys));
    }

    #[test]
    fn set_domains_separate_identical_elements() {
        let mut a = SetAccumulator::new(b"shekyl/test/table-a");
        let mut b = SetAccumulator::new(b"shekyl/test/table-b");
        a.insert(&elem(7));
        b.insert(&elem(7));
        assert_ne!(
            a.value(),
            b.value(),
            "two tables holding identical bytes must not fold to the same value"
        );
    }

    #[test]
    fn set_remove_of_a_never_inserted_element_silently_adds_it() {
        // Pins the documented limitation: `remove` cannot detect a wrong
        // argument. The type is an involution, not a set difference.
        let mut acc = SetAccumulator::new(KI);
        acc.remove(&elem(3));
        let mut mirror = SetAccumulator::new(KI);
        mirror.insert(&elem(3));
        assert_eq!(
            acc.value(),
            mirror.value(),
            "remove == insert; this is XOR, not a set"
        );
    }

    #[test]
    fn set_inserting_the_same_element_twice_cancels() {
        let mut acc = SetAccumulator::new(KI);
        acc.insert(&elem(4));
        acc.insert(&elem(4));
        assert_eq!(acc.value(), [0u8; 32], "XOR of a leaf with itself is zero");
    }
}
