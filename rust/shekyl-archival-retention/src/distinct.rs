// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shared all-distinct fold behind the block-level uniqueness passes.
//!
//! Every intra-block cross-tx uniqueness decision — emission `(P, E)` claims
//! ([`crate::claimed_epochs::emission_block_claims_unique`]) and per-`P` bond
//! posts ([`crate::bond_post::bond_post_block_unique`]) — is the same verdict:
//! no two entries equal. Each pass keeps its own named entry point (the key it
//! is keyed on is a consensus decision, documented there); the fold itself
//! lives once here so the next uniqueness pass in this family reuses the
//! audited implementation instead of a third paste.

/// True iff no two items in `items` are equal (sort + adjacent-inequality).
#[must_use]
pub fn all_distinct<T: Ord + Clone>(items: &[T]) -> bool {
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).all(|w| w[0] != w[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_singleton_are_distinct() {
        assert!(all_distinct::<u64>(&[]));
        assert!(all_distinct(&[7u64]));
    }

    #[test]
    fn detects_duplicates_regardless_of_position() {
        assert!(all_distinct(&[1u64, 2, 3]));
        assert!(!all_distinct(&[1u64, 1]));
        assert!(!all_distinct(&[1u64, 2, 1]));
        assert!(!all_distinct(&[2u64, 1, 2]));
    }
}
