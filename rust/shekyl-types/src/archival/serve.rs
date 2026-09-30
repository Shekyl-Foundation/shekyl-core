// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Serve-credit read answers (S-ARCH A3–A5): how many passes a pair recorded,
//! and which shards a persona has served.

use crate::{SettlementEpoch, ShardId};

// ---------------------------------------------------------------------------
// The serve-credit reads' answers (DRS-E1 S-ARCH A3–A5; on `ChainView`
// since DRS-E4 commit 2, which is why they are here and not in the store)
// ---------------------------------------------------------------------------

/// How many pass bits a `(persona, shard, epoch)` recorded — `PC-D5`'s
/// enumeration over the pair-epoch prefix. `u32` in the C++ (`PC-D5`'s
/// bound); the newtype keeps it from being added to an epoch. Admission
/// collapsed it to `> 0` while the beacon issued one challenge (CEN-J3's
/// dedup); the settlement writer and the assignment cutover's count bound
/// consume the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PassCount(u32);

impl PassCount {
    /// No pass bits.
    pub const ZERO: Self = Self(0);

    /// A count the reader tallied.
    #[must_use]
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }

    /// The count.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// Whether any pass was recorded — the admission arm's question.
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 > 0
    }
}

/// A served shard and the latest settlement epoch it earned a pass bit in
/// — one row of the served-shards read (S-ARCH A4), the release cooldown's
/// anchor (CEN-J16) and the drop arm's grace-tail operand (CEN-J17).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedShard {
    /// Which shard.
    pub shard: ShardId,
    /// The latest epoch with a pass bit for it.
    pub last_served: SettlementEpoch,
}
