// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `following_degraded` latch's value (`DRS_X_STORE_FLIP.md` DX-Q2
//! item 8; `P2P_3_CHAIN_SYNC_BRIEF.md` §A item 7).
//!
//! The latch says this node saw a heavier chain it refused, and it is one
//! way until a resync. What it stores is the evidence, not a flag: the fork
//! point, the heavier tip and that tip's work. An operator acting on the
//! latch needs to know which chain and how deep.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{exact, Canonical, CodecError};
use shekyl_types::{BlockHash, BlockHeight};

/// What set the latch: a heavier chain forking at `fork_at`, whose tip is
/// `tip` with cumulative work `work`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowingDegraded {
    /// The last height both chains share.
    pub fork_at: BlockHeight,
    /// The heavier chain's tip.
    pub tip: BlockHash,
    /// The heavier tip's cumulative difficulty.
    pub work: CumulativeDifficulty,
}

impl FollowingDegraded {
    const LEN: usize = 8 + 32 + 16;
}

impl Canonical for FollowingDegraded {
    const NAME: &'static str = "following_degraded";
    const FIXED_WIDTH: Option<usize> = Some(Self::LEN);

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fork_at.to_raw().to_le_bytes());
        out.extend_from_slice(self.tip.as_bytes());
        out.extend_from_slice(&self.work.to_raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let bytes = exact::<{ Self::LEN }>(Self::NAME, bytes)?;
        let fork_at = BlockHeight::from_raw(u64::from_le_bytes(
            bytes[0..8].try_into().expect("8 bytes by construction"),
        ));
        let tip = BlockHash::from_bytes(bytes[8..40].try_into().expect("32 bytes by construction"));
        let work = CumulativeDifficulty::from_raw(u128::from_le_bytes(
            bytes[40..56].try_into().expect("16 bytes by construction"),
        ));
        Ok(Self { fork_at, tip, work })
    }
}
