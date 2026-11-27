// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `Spread` fixture holds every input count the cost benches sweep.
//!
//! The benches sweep each depth's legal input counts (`max_inputs_at`), and
//! the derived cap reaches past `HELIOS_CHUNK_WIDTH`. One layer-1 Helios node
//! takes at most that many leaf chunks, so a fixture that gave each input
//! its own chunk could not be proved past it, and the floor run stopped at
//! the first such cell. The fixture deals the inputs over at most that many
//! chunks; these pin that it builds and verifies there, at the shallowest
//! spend depth and at the first projected one.

use rand_core::OsRng;

use shekyl_fcmp::tree::HELIOS_CHUNK_WIDTH;
use shekyl_verify_cost::relay::{admission_verify, build_fixture, ChunkLayout};

fn spread_past_the_width_verifies(tree_depth: u8) {
    let n_in = HELIOS_CHUNK_WIDTH + 1;
    let fixture = build_fixture(&mut OsRng, n_in, 2, tree_depth, ChunkLayout::Spread);
    let status = admission_verify(&fixture);
    assert!(
        status.verified(),
        "depth {tree_depth}, {n_in} spread inputs: {status:?}"
    );
}

#[test]
fn a_spread_fixture_past_the_helios_width_verifies_at_depth_two() {
    spread_past_the_width_verifies(2);
}

#[test]
fn a_spread_fixture_past_the_helios_width_verifies_at_depth_three() {
    spread_past_the_width_verifies(3);
}
