// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What an ordinary transaction pays in a run
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-1).
//!
//! The fee is an arm of the run, not a property of a scenario: every
//! scenario reads it from [`crate::engine::SimParams::fee`], so one value at
//! the top of a run decides what every fold charges, and a report cannot mix
//! two fees without saying so.

/// How a run prices an ordinary transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeModel {
    /// **Control arm — a declared divergence from production** (§4 of the
    /// design document). One flat fee per transaction at every height.
    ///
    /// The chain charges no such fee: its relay floor is
    /// `F = R·C·w_ref/M²`, proportional to the block reward. This arm
    /// exists because the tables in
    /// `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12.13–§12.14 were
    /// measured on it, and a control that reproduces them is what shows a
    /// later difference is the fee and nothing else.
    FlatControl {
        /// Atomic units per transaction.
        per_tx_atomic: u64,
    },
}

/// The flat fee the §12.13–§12.14 tables were measured on: `0.1 SKL`.
pub const SECTION_12_14_FLAT_FEE_ATOMIC: u64 = 100_000_000;

impl FeeModel {
    /// The control arm at the §12.13–§12.14 fee.
    pub const SECTION_12_14_CONTROL: Self = Self::FlatControl {
        per_tx_atomic: SECTION_12_14_FLAT_FEE_ATOMIC,
    };

    /// Atomic units one ordinary transaction pays.
    #[must_use]
    pub const fn per_tx_atomic(self) -> u64 {
        match self {
            Self::FlatControl { per_tx_atomic } => per_tx_atomic,
        }
    }
}
