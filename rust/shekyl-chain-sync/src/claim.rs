// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A peer's claim of its chain. A hint, never a target (CS-Q2 step 1).
//!
//! A chain of `n` blocks has at least `n` work: the genesis block's
//! target is 1 under every rule set, and every later block's target is
//! at least 1 (CEN-D6). A count of 0, or work below the count, cannot
//! be a chain.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, ChainCount};

/// What a peer says its chain is. The handshake and an announce both
/// arrive as this, and a headers response's `tip_work` replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerClaim {
    /// The peer's block count: the handshake's `current_height`.
    /// Genesis alone is 1. A count, not an ordinal
    /// (`HEIGHT_SEMANTICS.md` C9).
    pub count: ChainCount,
    /// The peer's cumulative work through those blocks.
    pub work: CumulativeDifficulty,
    /// The tip the peer named: the handshake's `top_id`. When this node
    /// holds that block in `T`, it is a frontier the session named
    /// (CS-F8): enough to ask the session for bodies along it, never a
    /// reason to trust them. A response's `tip_work` carries no hash and
    /// leaves it.
    pub top: BlockHash,
}

/// The claim cannot be a chain. This is the whole of `PayloadRefused`
/// (CS-F1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadRefused {
    /// A block count of 0. Every chain has genesis, so the count is at
    /// least 1.
    Height,
    /// Cumulative work below the block count.
    Work,
}

pub(crate) fn admit(claim: PeerClaim) -> Result<PeerClaim, PayloadRefused> {
    let count = claim.count.to_raw();
    if count == 0 {
        return Err(PayloadRefused::Height);
    }
    if claim.work.to_raw() < u128::from(count) {
        return Err(PayloadRefused::Work);
    }
    Ok(claim)
}
