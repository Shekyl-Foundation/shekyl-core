// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Funding-input floor tests — sibling of `bond_post_tests.rs` so that
//! file stays under 1k (the predicate is a count rule; it does not belong
//! in the per-kind verifier suite).

use super::bond_post_funding_floor_met;

/// The funding-input floor, at its boundary.
///
/// A count rule reduces to one comparison, so the test that matters is the pair
/// either side of it: nothing admits nothing, and one real input is enough for
/// every post kind (the floor is a shape rule — how much those inputs carry is
/// the amount rules' business, and they run after it).
///
/// This is the wallet's rule too: `require_funding_inputs` calls this
/// predicate rather than restating the condition, so a change made here
/// reaches both producers instead of drifting away from it.
#[test]
fn the_funding_floor_refuses_none_and_admits_one() {
    assert!(!bond_post_funding_floor_met(0));
    assert!(bond_post_funding_floor_met(1));
    assert!(bond_post_funding_floor_met(8));
}
