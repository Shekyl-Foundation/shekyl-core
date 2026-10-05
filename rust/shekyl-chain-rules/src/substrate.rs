// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a rule may ask of the environment that is **not** the recorded
//! chain: a clock, and a RandomX longhash (`CHAIN_RULES_SLICE_2.md` §4.2,
//! Q1 as ruled).
//!
//! [`ChainView`](crate::ChainView) answers about the chain a block connects
//! onto; [`Substrate`] answers about the world it connects *in* — what time
//! it is (CEN-C1), and what RandomX v2 makes of the block's PoW preimage
//! under a seed (CEN-D2). Neither is a rule-set parameter, neither is
//! chain state, and a rule that reached for either directly (`std::time`,
//! a RandomX crate) would be untestable and would drag a 256 MB cache and a
//! VM into a crate whose whole design is "unit-testable against a mock with
//! no database" (G1's spirit; the closure the belt records is unchanged by
//! this trait).
//!
//! # Where it plugs in
//!
//! Into the **stateless stage** — [`form`](crate::form) — and not into
//! [`validate`](crate::validate). C2-R8 Q3 projects the `ChainView` from
//! the exclusive write transaction that applies the block, so `validate`
//! runs inside that transaction; RandomX is the most expensive call in the
//! validator, and running it there would serialize IBD behind the write
//! lock. `form` runs outside, in parallel, with no view; what it computes
//! travels to `validate` inside a [`StructurallyValid`](crate::StructurallyValid).
//!
//! # Faults are not verdicts
//!
//! A substrate that cannot answer — the verifier failed, the clock is
//! unavailable — returns its own [`Substrate::Fault`], opaque to every rule
//! and returned in the outer position of `form`. A block whose longhash
//! could not be computed is **unproven, not disproven** (`blockchain.cpp:5520`–`:5531`:
//! "rejected unverified"); no rule maps a substrate fault onto an
//! `InvalidBlock`, and the sentinel-hash belt the C++ needed (`0xff…`,
//! CEN-D2's note) cannot be written here — there is no hash to return on
//! failure, only the fault.

use shekyl_types::{BlockHash, PowHash, Timestamp};

/// The environment a block is judged in: a wall clock and a PoW verifier.
///
/// Implemented by the daemon over its clock and its RandomX cache /
/// precompute table (`m_blocks_longhash_table` is this trait with a C++
/// type); by the crate's test harness over fixture values. Never by the
/// store: the store knows the chain, not the world.
pub trait Substrate {
    /// What this substrate can fail with — the verifier's error, the
    /// clock's. Opaque to every rule (no bound). A fault is not a verdict.
    type Fault;

    /// The local wall clock, Unix seconds (CEN-C1's operand). Read once per
    /// [`form`](crate::form) and carried on the verdict, so the FTL leg is
    /// judged against one instant and a consumer can see which.
    fn local_clock(&self) -> Result<Timestamp, Self::Fault>;

    /// RandomX v2 over `pow_blob` under `seed` (CEN-D2). The rule chooses
    /// `seed` (CEN-D3: the block id at `seedheight(h)`); the implementor
    /// may cache by it. An `Err` is the fail-closed gate: the block cannot
    /// be proven, and `form` returns the fault instead of a verdict.
    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault>;

    /// `seed` is about to serve a run of blocks (CEN-D3's epoch). An
    /// implementor that caches by seed may prepare and pin it now, off the
    /// hot path, so the first block of the epoch does not pay the cache
    /// fill inside [`longhash`](Self::longhash) and two live seeds of a lag
    /// window do not evict each other. Advisory: `longhash` is correct
    /// whether or not this was called. The default does nothing.
    fn pin_seed(&self, _seed: &BlockHash) {}
}
