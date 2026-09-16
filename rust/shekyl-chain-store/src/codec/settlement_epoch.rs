// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The datadir schedule pin: blocks per archival settlement epoch, as the
//! file was built under (S-CHAIN-W SCW-2; C++ `set_settlement_epoch_blocks_pin`,
//! `db_lmdb.cpp`, and the `Blockchain::init` check that consumed it).
//!
//! Persisted epoch-derived state — bond join epochs, serve-credit windows —
//! is only meaningful under the schedule it was written with. The C++ pinned
//! the schedule on FAKECHAIN only, because that is the one network where the
//! lever (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS`) can move it; here the pin is
//! written on every network (rule 71: the store sees a datum, never a
//! nettype), which on a public network is a constant matching a constant.
//! What the store owns is **record at create, compare at open, refuse
//! loudly on mismatch** — the same shape as `schema_version`. Which value
//! is *effective* is the caller's (`shekyl-archival-retention`); the store
//! never reads the environment.
//!
//! `0` is not a schedule: the C++ used it as "unpinned", and a file this
//! crate wrote is never unpinned, so a zero cell is corruption (SI-7), not
//! a state.

use core::num::NonZeroU64;

use super::{Canonical, CodecError};

/// Blocks per settlement epoch, pinned into the store header at create.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettlementEpochBlocks(NonZeroU64);

impl SettlementEpochBlocks {
    /// `blocks` per epoch; `None` for zero, which names no schedule.
    #[must_use]
    pub const fn new(blocks: u64) -> Option<Self> {
        match NonZeroU64::new(blocks) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The schedule, in blocks.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl core::fmt::Display for SettlementEpochBlocks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} blocks/epoch", self.0)
    }
}

impl Canonical for SettlementEpochBlocks {
    /// Also the `properties` key the C++ wrote (`"settlement_epoch_blocks"`),
    /// so a cell this crate reads back is the one that store pinned.
    const NAME: &'static str = "settlement_epoch_blocks";
    const FIXED_WIDTH: Option<usize> = Some(8);

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.get().encode_into(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let blocks = u64::decode(bytes).map_err(|e| e.in_codec(Self::NAME))?;
        Self::new(blocks).ok_or(CodecError::Invalid {
            codec: Self::NAME,
            reason: "zero blocks per epoch names no schedule",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_as_u64_le_and_refuses_zero_and_wrong_widths() {
        let pin = SettlementEpochBlocks::new(10_000).expect("non-zero");
        assert_eq!(pin.encode(), 10_000u64.to_le_bytes());
        assert_eq!(SettlementEpochBlocks::decode(&pin.encode()), Ok(pin));
        assert_eq!(pin.to_string(), "10000 blocks/epoch");
        assert_eq!(SettlementEpochBlocks::new(0), None);
        assert_eq!(
            SettlementEpochBlocks::decode(&[0; 8]),
            Err(CodecError::Invalid {
                codec: "settlement_epoch_blocks",
                reason: "zero blocks per epoch names no schedule",
            })
        );
        assert_eq!(
            SettlementEpochBlocks::decode(&[1, 0]),
            Err(CodecError::Length {
                codec: "settlement_epoch_blocks",
                expected: 8,
                actual: 2,
            })
        );
    }
}
