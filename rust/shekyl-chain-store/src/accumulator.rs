// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Incremental accumulator primitives (DRS-0 slice A, `DAEMON_REDB_STORE.md`
//! §6.2).
//!
//! [`digest_v0`](crate::digest_v0) is a **full-domain** oracle: it rescans
//! every element on every call, which is `O(n)` per block and `O(n²)` over a
//! sync. §6.2 freezes the incremental replacements. This module is the two
//! *incremental* classes; the other three need no state.
//!
//! | §6.2 class | Type here | Why |
//! |---|---|---|
//! | Set-shaped | [`SetAccumulator`] | order-independent XOR fold |
//! | Append-mostly | [`AppendAccumulator`] | running chained hash |
//! | Small | — | full-domain digest every block; nothing to carry |
//! | `derived` | — | recomputed from a named source at checkpoints |
//! | `excluded` | — | not folded |
//!
//! The per-table class assignment for all 49 tables is the `Accumulator
//! class` column of
//! [`docs/LMDB_WRITE_ATOMICITY_AUDIT.md`](../../../docs/LMDB_WRITE_ATOMICITY_AUDIT.md)
//! §10, defined in that document's §12.
//!
//! # What these types fold
//!
//! **A canonical encoding of the decoded logical value, never storage
//! bytes.** This is forced by DRS-E2: the C++ LMDB store and the Rust redb
//! store must produce the *same* digest for the same logical state, and they
//! will never agree on layout. Both accumulators therefore take `&[u8]`
//! element encodings and say nothing about how a row is stored.
//!
//! # The reversal rule these types cannot enforce
//!
//! §12's falsifier run establishes that every delete path in the LMDB store
//! reads the row back before deleting, so the stored element is always
//! available at delete. The design rule that follows is: **fold the value
//! read from the store, never the caller's argument.** DRS-W13 is why — the
//! curve pop *reconstructs* `TreePosition` arithmetically, so a fold over
//! the caller's argument would inherit the reconstruction.
//!
//! # Relationship to the shipped v0 oracle
//!
//! [`SetAccumulator`] over
//! [`digest_v0::SPENT_ELEM_CUSTOMIZATION`](crate::digest_v0::SPENT_ELEM_CUSTOMIZATION)
//! reproduces [`digest_v0::spent_accumulator`](crate::digest_v0::spent_accumulator)
//! byte for byte — asserted by test, so the incremental form is a drop-in
//! for the full-domain one and DRS-E2 can compare across the two.
//!
//! [`AppendAccumulator`] is **not** equivalent to
//! [`digest_v0::chain_component`](crate::digest_v0::chain_component): that
//! function folds the block count into its preimage and hashes the whole
//! height-ordered sequence in one pass, which is a different shape from a
//! per-element chain. Adopting [`AppendAccumulator`] for `blocks` is
//! therefore a [`DIGEST_FORMAT_VERSION`](crate::digest_v0::DIGEST_FORMAT_VERSION)
//! bump, not a refactor, and DRS-E1 must not assume equivalence.
//!
//! [`SetAccumulator::remove`] cannot check this. It XORs whatever it is
//! given, and XORing an element that was never inserted silently *adds* it —
//! the operation is an involution, not a set difference. That is the
//! property that makes it pop-symmetric and the property that makes it
//! unable to detect a wrong argument. Detection is the checkpoint
//! reconciliation's job (§6.2's fourth row), not this type's.

use shekyl_crypto_hash::cshake256_32;

/// XOR of per-element hashes — §6.2's **set-shaped** class.
///
/// Order-independent, so the fold does not depend on comparator order. This
/// matters concretely: `compare_hash32` orders three set-shaped tables'
/// duplicates as a little-endian 256-bit integer rather than
/// lexicographically (audit §12), and an order-independent fold is why that
/// wart never reaches a digest.
///
/// [`insert`](Self::insert) and [`remove`](Self::remove) are the **same
/// operation**. XOR is an involution, which is exactly what "pop-symmetric
/// by construction" means — and see the module note on what that costs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAccumulator {
    /// cSHAKE customization for this table's leaves. Per-table, so two
    /// tables holding identical bytes do not fold to the same value.
    element_domain: &'static [u8],
    acc: [u8; 32],
}

impl SetAccumulator {
    /// Empty accumulator over `element_domain`.
    ///
    /// The domain is required rather than defaulted: two tables whose
    /// elements are both bare 32-byte hashes would otherwise cancel each
    /// other out across a combined digest.
    #[must_use]
    pub const fn new(element_domain: &'static [u8]) -> Self {
        Self {
            element_domain,
            acc: [0u8; 32],
        }
    }

    /// Fold `element`'s canonical encoding in.
    pub fn insert(&mut self, element: &[u8]) {
        self.toggle(element);
    }

    /// Fold `element`'s canonical encoding back out.
    ///
    /// Identical to [`insert`](Self::insert). `element` must be the encoding
    /// **read back from the store**, not a caller-reconstructed value.
    pub fn remove(&mut self, element: &[u8]) {
        self.toggle(element);
    }

    fn toggle(&mut self, element: &[u8]) {
        let leaf = cshake256_32(self.element_domain, element);
        for (dst, src) in self.acc.iter_mut().zip(leaf.iter()) {
            *dst ^= *src;
        }
    }

    /// Current accumulator value. All-zero for an empty table.
    #[must_use]
    pub const fn value(&self) -> [u8; 32] {
        self.acc
    }
}

/// A point an [`AppendAccumulator`] can be rewound to.
///
/// This type exists because §6.2's Append-mostly row does **not** grant
/// pop-symmetry by construction, and the audit's §12 finding 1 says so: a
/// running chained hash cannot be reversed one step without retaining the
/// prior state. Rewinding therefore requires a checkpoint someone chose to
/// take, and that obligation is visible in the API rather than left to a
/// comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    state: [u8; 32],
    len: u64,
}

impl Checkpoint {
    /// Number of elements folded at the time this checkpoint was taken.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the checkpoint was taken over an empty accumulator.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Running chained hash — §6.2's **append-mostly** class.
///
/// `H_n = cSHAKE(domain, H_{n-1} ‖ n-1 ‖ x_n)`. Order-dependent by design:
/// the block corpus has an order and the digest should see a reordering.
///
/// **There is deliberately no one-element `pop`.** Reversing a chained hash
/// needs `H_{n-1}`, which this type does not retain, so the only way back is
/// [`rewind_to`](Self::rewind_to) with a [`Checkpoint`] taken earlier. A
/// `pop` that recomputed the prior state from the remaining elements would
/// be a full-domain rescan wearing an incremental method's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendAccumulator {
    chain_domain: &'static [u8],
    state: [u8; 32],
    len: u64,
}

impl AppendAccumulator {
    /// Empty accumulator over `chain_domain`.
    #[must_use]
    pub const fn new(chain_domain: &'static [u8]) -> Self {
        Self {
            chain_domain,
            state: [0u8; 32],
            len: 0,
        }
    }

    /// Chain `element`'s canonical encoding onto the running hash.
    ///
    /// The preimage is `H_{n-1} ‖ x_n`, and it is unambiguous without a
    /// length field because `H_{n-1}` is a fixed-width 32-byte prefix and
    /// the element is the whole variable-length tail.
    ///
    /// An earlier draft also folded the element index here, on the stated
    /// grounds that it stopped a truncate-and-refill collision. It did not:
    /// removing it left every test green, because position and state always
    /// advance together and no caller can set one without the other. It was
    /// dropped rather than kept as defence-in-depth — this encoding is
    /// frozen and consensus-visible, so a field no behaviour depends on is a
    /// commitment with no benefit.
    pub fn push(&mut self, element: &[u8]) {
        let mut preimage = Vec::with_capacity(32 + element.len());
        preimage.extend_from_slice(&self.state);
        preimage.extend_from_slice(element);
        self.state = cshake256_32(self.chain_domain, &preimage);
        self.len += 1;
    }

    /// Take a checkpoint that [`rewind_to`](Self::rewind_to) can restore.
    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            state: self.state,
            len: self.len,
        }
    }

    /// Restore a previously taken checkpoint.
    ///
    /// This is the *only* way back. Rewinding to a checkpoint taken at a
    /// greater length than the current one is a caller error — it would
    /// fabricate state this accumulator never folded — and is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`RewindError::Forward`] if the checkpoint is ahead of the
    /// current position.
    pub fn rewind_to(&mut self, checkpoint: Checkpoint) -> Result<(), RewindError> {
        if checkpoint.len > self.len {
            return Err(RewindError::Forward {
                checkpoint: checkpoint.len,
                current: self.len,
            });
        }
        self.state = checkpoint.state;
        self.len = checkpoint.len;
        Ok(())
    }

    /// Current accumulator value. All-zero for an empty table.
    #[must_use]
    pub const fn value(&self) -> [u8; 32] {
        self.state
    }

    /// Number of elements folded so far.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing has been folded yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Why a [`rewind_to`](AppendAccumulator::rewind_to) was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewindError {
    /// The checkpoint is ahead of the accumulator's current position.
    Forward {
        /// Length recorded in the checkpoint.
        checkpoint: u64,
        /// Length the accumulator is actually at.
        current: u64,
    },
}

impl core::fmt::Display for RewindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Forward {
                checkpoint,
                current,
            } => write!(
                f,
                "cannot rewind forward: checkpoint is at {checkpoint} elements, \
                 accumulator is at {current}"
            ),
        }
    }
}

impl core::error::Error for RewindError {}

#[cfg(test)]
mod tests {
    use super::*;

    const KI: &[u8] = b"shekyl/test/spent-elem";
    const CHAIN: &[u8] = b"shekyl/test/chain";

    fn elem(n: u8) -> [u8; 32] {
        [n; 32]
    }

    // --- Set-shaped: the property the whole class rests on -------------

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
        // Not a bug being tested green: this pins the documented limitation
        // that makes `remove` unable to detect a wrong argument. The type is
        // an involution, not a set difference, and audit §12 routes detection
        // to checkpoint reconciliation rather than to this method.
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

    // --- Append-mostly: order matters, and one step back does not exist --

    #[test]
    fn append_is_order_dependent() {
        let mut a = AppendAccumulator::new(CHAIN);
        let mut b = AppendAccumulator::new(CHAIN);
        a.push(&elem(1));
        a.push(&elem(2));
        b.push(&elem(2));
        b.push(&elem(1));
        assert_ne!(a.value(), b.value(), "a chained hash must see a reordering");
    }

    #[test]
    fn append_rewind_to_checkpoint_restores_exactly() {
        let mut acc = AppendAccumulator::new(CHAIN);
        acc.push(&elem(1));
        acc.push(&elem(2));
        let cp = acc.checkpoint();
        let at_cp = acc.value();
        for n in 3..10 {
            acc.push(&elem(n));
        }
        assert_ne!(acc.value(), at_cp);
        acc.rewind_to(cp).expect("rewinding backwards is allowed");
        assert_eq!(
            acc.value(),
            at_cp,
            "rewind must restore the checkpointed state"
        );
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn append_replaying_after_a_rewind_reproduces_the_same_chain() {
        // This is the pop-by-checkpoint property in full: rewind, re-apply
        // the same elements, land on the same value.
        let mut acc = AppendAccumulator::new(CHAIN);
        let cp = acc.checkpoint();
        for n in 0..5 {
            acc.push(&elem(n));
        }
        let original = acc.value();
        acc.rewind_to(cp).expect("rewind to genesis");
        for n in 0..5 {
            acc.push(&elem(n));
        }
        assert_eq!(acc.value(), original);
    }

    #[test]
    fn append_cannot_rewind_forward() {
        let mut acc = AppendAccumulator::new(CHAIN);
        for n in 0..4 {
            acc.push(&elem(n));
        }
        let ahead = acc.checkpoint();
        let mut behind = AppendAccumulator::new(CHAIN);
        behind.push(&elem(0));
        let err = behind
            .rewind_to(ahead)
            .expect_err("forward rewind must be refused");
        assert_eq!(
            err,
            RewindError::Forward {
                checkpoint: 4,
                current: 1
            }
        );
    }

    #[test]
    fn append_distinguishes_chains_of_equal_length() {
        // Named for what it actually proves. Its predecessor claimed to test
        // an element-index binding in the preimage and did not: deleting that
        // field left this green, which is how the field came out.
        let mut a = AppendAccumulator::new(CHAIN);
        let mut b = AppendAccumulator::new(CHAIN);
        a.push(&elem(1));
        a.push(&elem(1));
        b.push(&elem(2));
        b.push(&elem(2));
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn append_prefix_is_not_the_whole_chain() {
        // A chain must not equal its own prefix: pushing advances the value.
        let mut acc = AppendAccumulator::new(CHAIN);
        acc.push(&elem(1));
        let after_one = acc.value();
        acc.push(&elem(2));
        assert_ne!(acc.value(), after_one);
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn append_domains_separate_identical_chains() {
        let mut a = AppendAccumulator::new(b"shekyl/test/chain-a");
        let mut b = AppendAccumulator::new(b"shekyl/test/chain-b");
        a.push(&elem(5));
        b.push(&elem(5));
        assert_ne!(a.value(), b.value());
    }

    #[test]
    fn append_empty_accumulator_is_all_zero_and_empty() {
        let acc = AppendAccumulator::new(CHAIN);
        assert_eq!(acc.value(), [0u8; 32]);
        assert!(acc.is_empty());
        assert!(acc.checkpoint().is_empty());
    }
}
