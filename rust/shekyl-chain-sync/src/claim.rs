// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A peer's claim of its chain. A hint, never a target (CS-Q2 step 1).

use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
use shekyl_types::BlockHeight;

/// What a peer says its chain is. The handshake and an announce both
/// arrive as this, and a headers response's `tip_work` replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerClaim {
    /// The peer's chain height.
    pub height: BlockHeight,
    /// The peer's cumulative work.
    pub work: CumulativeDifficulty,
}

/// The claim cannot be a chain. This is the whole of `PayloadRefused`
/// (CS-F1): height 0, since every chain has genesis, or work below
/// [`GENESIS_DIFFICULTY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadRefused {
    /// Height 0. Every chain has genesis.
    Height,
    /// Cumulative work below [`GENESIS_DIFFICULTY`]. The genesis block's
    /// own proof is difficulty 1, so a peer that has only genesis is
    /// refused here.
    Work,
}

pub(crate) fn admit(claim: PeerClaim) -> Result<PeerClaim, PayloadRefused> {
    if claim.height.is_zero() {
        return Err(PayloadRefused::Height);
    }
    if claim.work.to_raw() < GENESIS_DIFFICULTY {
        return Err(PayloadRefused::Work);
    }
    Ok(claim)
}
