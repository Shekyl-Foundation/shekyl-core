// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `following_degraded` latch's value (`DRS_X_STORE_FLIP.md` DX-Q2
//! item 8; `P2P_3_CHAIN_SYNC_BRIEF.md` §A item 7).
//!
//! The latch says this node's view of the chain needs an operator's
//! attention, and it is one way until a resync. What it stores is the
//! evidence, not a flag, in one of two kinds:
//!
//! - a heavier chain this node refused (past the reorg cap, or below the
//!   undo floor): the fork point, the heavier tip and that tip's work;
//! - a switch this node made that popped more blocks than the lock window
//!   (S1, design review 2026-11-03): followed, and reported, never refused.
//!   A switch that deep un-confirms outputs a wallet already treated as
//!   spendable.
//!
//! An operator acting on the latch needs to know which chain and how deep.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{exact, Canonical, CodecError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

/// What set the latch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowingDegraded {
    /// A heavier chain forking at `fork_at`, whose tip is `tip` with
    /// cumulative work `work`, that this node did not follow.
    HeavierRefused {
        /// The last height both chains share.
        fork_at: BlockHeight,
        /// The heavier chain's tip.
        tip: BlockHash,
        /// The heavier tip's cumulative difficulty.
        work: CumulativeDifficulty,
    },
    /// A switch this node made, popping `depth` blocks above `fork_at`, from
    /// `old_tip` to `new_tip`.
    DeepReorg {
        /// The recorded blocks the switch popped.
        depth: BlockCount,
        /// The last height both chains share.
        fork_at: BlockHeight,
        /// The tip the switch left.
        old_tip: BlockHash,
        /// The tip the switch connected.
        new_tip: BlockHash,
    },
}

/// The kind's tag, the first byte of the encoding.
const HEAVIER_REFUSED: u8 = 0;
const DEEP_REORG: u8 = 1;
/// `tag ‖ fork_at_le8 ‖ tip[32] ‖ work_le16`.
const HEAVIER_REFUSED_LEN: usize = 1 + 8 + 32 + 16;
/// `tag ‖ depth_le8 ‖ fork_at_le8 ‖ old_tip[32] ‖ new_tip[32]`.
const DEEP_REORG_LEN: usize = 1 + 8 + 8 + 32 + 32;

fn le8(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8 bytes by construction"))
}

fn hash(bytes: &[u8]) -> BlockHash {
    BlockHash::from_bytes(bytes.try_into().expect("32 bytes by construction"))
}

impl Canonical for FollowingDegraded {
    const NAME: &'static str = "following_degraded";
    /// Two kinds, two lengths: the tag says which.
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        match *self {
            Self::HeavierRefused { fork_at, tip, work } => {
                out.push(HEAVIER_REFUSED);
                out.extend_from_slice(&fork_at.to_raw().to_le_bytes());
                out.extend_from_slice(tip.as_bytes());
                out.extend_from_slice(&work.to_raw().to_le_bytes());
            }
            Self::DeepReorg {
                depth,
                fork_at,
                old_tip,
                new_tip,
            } => {
                out.push(DEEP_REORG);
                out.extend_from_slice(&depth.to_raw().to_le_bytes());
                out.extend_from_slice(&fork_at.to_raw().to_le_bytes());
                out.extend_from_slice(old_tip.as_bytes());
                out.extend_from_slice(new_tip.as_bytes());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        match bytes.first() {
            Some(&HEAVIER_REFUSED) => {
                let bytes = exact::<HEAVIER_REFUSED_LEN>(Self::NAME, bytes)?;
                Ok(Self::HeavierRefused {
                    fork_at: BlockHeight::from_raw(le8(&bytes[1..9])),
                    tip: hash(&bytes[9..41]),
                    work: CumulativeDifficulty::from_raw(u128::from_le_bytes(
                        bytes[41..57].try_into().expect("16 bytes by construction"),
                    )),
                })
            }
            Some(&DEEP_REORG) => {
                let bytes = exact::<DEEP_REORG_LEN>(Self::NAME, bytes)?;
                Ok(Self::DeepReorg {
                    depth: BlockCount::from_raw(le8(&bytes[1..9])),
                    fork_at: BlockHeight::from_raw(le8(&bytes[9..17])),
                    old_tip: hash(&bytes[17..49]),
                    new_tip: hash(&bytes[49..81]),
                })
            }
            _ => Err(CodecError::Invalid {
                codec: Self::NAME,
                reason: "the latch's kind tag is not one this binary wrote",
            }),
        }
    }
}
