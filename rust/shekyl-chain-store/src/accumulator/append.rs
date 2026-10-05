// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Running chained hash — §6.2's append-mostly class.

use core::fmt;

use shekyl_crypto_hash::cshake256_32;

use super::domain::AccumulatorDomain;

/// A point an [`AppendAccumulator`] can be rewound to.
///
/// Carries the domain it was taken under. Restoring a checkpoint from a
/// different chain would hash subsequent elements under the wrong
/// customization over foreign prior state — a silent digest divergence.
/// [`AppendAccumulator::rewind_to`] refuses that.
///
/// This type exists because §6.2's Append-mostly row does **not** grant
/// pop-symmetry by construction: a running chained hash cannot be reversed
/// one step without retaining the prior state. Rewinding therefore requires
/// a checkpoint someone chose to take, and that obligation is visible in
/// the API rather than left to a comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    domain: AccumulatorDomain,
    state: [u8; 32],
    len: u64,
}

impl Checkpoint {
    /// Domain this checkpoint was taken under.
    #[must_use]
    pub const fn domain(self) -> AccumulatorDomain {
        self.domain
    }

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
/// `H_n = cSHAKE(domain, H_{n-1} ‖ x_n)`. Order-dependent by design: the
/// block corpus has an order and the digest should see a reordering.
/// `H_{n-1}` is a fixed-width 32-byte prefix, so the preimage is
/// unambiguous without a length or index field.
///
/// **There is deliberately no one-element `pop`.** Reversing a chained hash
/// needs `H_{n-1}`, which this type does not retain, so the only way back is
/// [`rewind_to`](Self::rewind_to) with a [`Checkpoint`] taken earlier. A
/// `pop` that recomputed the prior state from the remaining elements would
/// be a full-domain rescan wearing an incremental method's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendAccumulator {
    chain_domain: AccumulatorDomain,
    state: [u8; 32],
    len: u64,
}

impl AppendAccumulator {
    /// Empty accumulator over `chain_domain`.
    ///
    /// # Panics
    ///
    /// Panics if `chain_domain` is empty.
    #[must_use]
    pub const fn new(chain_domain: &'static [u8]) -> Self {
        Self {
            chain_domain: AccumulatorDomain::new(chain_domain),
            state: [0u8; 32],
            len: 0,
        }
    }

    /// Chain `element`'s canonical encoding onto the running hash.
    ///
    /// The preimage is `H_{n-1} ‖ x_n`. Position and state always advance
    /// together, so an element index in the preimage would be a
    /// consensus-visible field no behaviour depends on.
    pub fn push(&mut self, element: &[u8]) {
        let mut preimage = Vec::with_capacity(32 + element.len());
        preimage.extend_from_slice(&self.state);
        preimage.extend_from_slice(element);
        self.state = cshake256_32(self.chain_domain.as_bytes(), &preimage);
        self.len += 1;
    }

    /// Take a checkpoint that [`rewind_to`](Self::rewind_to) can restore.
    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            domain: self.chain_domain,
            state: self.state,
            len: self.len,
        }
    }

    /// Restore a previously taken checkpoint of *this* chain.
    ///
    /// This is the *only* way back. Rewinding to a checkpoint taken at a
    /// greater length than the current one is a caller error — it would
    /// fabricate state this accumulator never folded — and is rejected.
    /// A checkpoint taken under a different domain is also rejected: it
    /// is not a point on this chain.
    ///
    /// # Errors
    ///
    /// Returns [`RewindError::Forward`] if the checkpoint is ahead of the
    /// current position, or [`RewindError::DomainMismatch`] if it was
    /// taken under a different customization.
    pub fn rewind_to(&mut self, checkpoint: Checkpoint) -> Result<(), RewindError> {
        if checkpoint.domain != self.chain_domain {
            return Err(RewindError::DomainMismatch {
                checkpoint: checkpoint.domain,
                current: self.chain_domain,
            });
        }
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
    /// The checkpoint was taken under a different cSHAKE customization.
    DomainMismatch {
        /// Domain recorded in the checkpoint.
        checkpoint: AccumulatorDomain,
        /// Domain this accumulator was constructed with.
        current: AccumulatorDomain,
    },
}

impl fmt::Display for RewindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward {
                checkpoint,
                current,
            } => write!(
                f,
                "cannot rewind forward: checkpoint is at {checkpoint} elements, \
                 accumulator is at {current}"
            ),
            Self::DomainMismatch {
                checkpoint,
                current,
            } => write!(
                f,
                "cannot rewind across domains: checkpoint is {checkpoint}, \
                 accumulator is {current}"
            ),
        }
    }
}

impl core::error::Error for RewindError {}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &[u8] = b"shekyl/test/chain";

    fn elem(n: u8) -> [u8; 32] {
        [n; 32]
    }

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
    fn append_cannot_rewind_across_domains() {
        let mut a = AppendAccumulator::new(b"shekyl/test/chain-a");
        a.push(&elem(1));
        a.push(&elem(2));
        let cp = a.checkpoint();
        let mut b = AppendAccumulator::new(b"shekyl/test/chain-b");
        b.push(&elem(1));
        b.push(&elem(2));
        let err = b
            .rewind_to(cp)
            .expect_err("a checkpoint is not portable across domains");
        assert_eq!(
            err,
            RewindError::DomainMismatch {
                checkpoint: AccumulatorDomain::new(b"shekyl/test/chain-a"),
                current: AccumulatorDomain::new(b"shekyl/test/chain-b"),
            }
        );
        // State is untouched on refusal.
        let mut expected = AppendAccumulator::new(b"shekyl/test/chain-b");
        expected.push(&elem(1));
        expected.push(&elem(2));
        assert_eq!(b.value(), expected.value());
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn append_distinguishes_chains_of_equal_length() {
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
        assert_eq!(acc.checkpoint().domain(), AccumulatorDomain::new(CHAIN));
    }
}
