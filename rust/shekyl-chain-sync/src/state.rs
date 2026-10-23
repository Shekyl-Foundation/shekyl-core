// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The derived sync state (CS-Q2 step 8). None of these is latched.
//! The alarm is the store's latch, read beside the state, and it never
//! replaces one of these.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::BlockHeight;

/// What sync publishes. Derived on every change from verified work, the
/// sessions, and the fill. A claim's value never appears here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// No session has completed a handshake.
    NoView,
    /// `work(L)` is less than the best verified work.
    Behind {
        /// Work through the local tip.
        have: CumulativeDifficulty,
        /// Work of the best verified chain.
        best: CumulativeDifficulty,
    },
    /// On the best verified chain, while the backward fill is short of
    /// its checkpoint. `verified_to` is the fill's descending frontier.
    Following {
        /// The fill's frontier.
        verified_to: BlockHeight,
    },
    /// On the best verified chain, and the fill has reached its checkpoint.
    Synced,
}
