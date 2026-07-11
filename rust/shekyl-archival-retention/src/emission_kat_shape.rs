// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The canonical emission KAT fixture **shape** — two bonds, two shards,
//! three credits — shared by the consensus verify KATs
//! (`tests/emission_verify_kat.rs`) and the wallet claim builder's KATs
//! (`shekyl-engine-core`'s `engine/emission_claim.rs`).
//!
//! The two suites are differential halves of one pin (the builder's step-7
//! self-check runs the landed verifier), so they must exercise **the same
//! fixture shape**: a bug found and fixed against one suite's fixture must
//! reproduce against the other's. Each suite still maps this shape into its
//! own types (borrowing verify views vs. owned wallet-side snapshots) and
//! sources its own consensus constants — only the *data* that could drift
//! is single-sourced here.
//!
//! Const data only, no logic: negligible in production builds, and homed in
//! this crate (not a test-support module) because pinned KAT vectors are
//! first-class consensus artifacts (`30-cryptography.mdc`).

/// The pinned shape values. Freeze heights are **offsets below**
/// `epoch_close_height(E)` (the fixture epoch is each suite's to choose);
/// credit pairs are `(bond_idx, shard_idx)` index tuples.
#[derive(Debug, Clone, Copy)]
pub struct EmissionKatShape {
    /// Both bond rows' `join_settlement_epoch` (claimant = idx 0, other =
    /// idx 1) **and** the claimant record's `E_join`: fixture epochs must be
    /// `≥ join + 1` to clear verify's step-2 bound.
    pub join_settlement_epoch: u64,
    /// The claimant-credited shard (`R_market = 2`: both bonds credit it).
    pub shard_a: u64,
    /// The other-bond-only shard (`R_market = 1`).
    pub shard_b: u64,
    /// `h_close(E) − freeze_height` for shard A.
    pub shard_a_freeze_offset: u64,
    /// `h_close(E) − freeze_height` for shard B.
    pub shard_b_freeze_offset: u64,
    /// Serve credits: {claimant→A, other→A, other→B}.
    pub credit_pairs: [(usize, usize); 3],
    /// The claimant's index into the bond rows.
    pub claimant_bond_idx: usize,
}

/// The canonical shape: claimant work is exactly its shard-A term
/// (`R_market(A) = 2`, `R_market(B) = 1`).
pub const EMISSION_KAT_SHAPE: EmissionKatShape = EmissionKatShape {
    join_settlement_epoch: 1,
    shard_a: 7,
    shard_b: 9,
    shard_a_freeze_offset: 5_000,
    shard_b_freeze_offset: 8_000,
    credit_pairs: [(0, 0), (1, 0), (1, 1)],
    claimant_bond_idx: 0,
};
