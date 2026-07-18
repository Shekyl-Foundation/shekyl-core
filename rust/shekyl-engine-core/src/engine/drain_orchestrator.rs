// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D1 projection — the drain trust boundary
//! (`ARCHIVAL_FIREWALL_GATE6.md` §12.3, the drain-amount taint-carve).
//!
//! The `P` value-out (drain) path has three stages, each reading the
//! minimum:
//!
//! - **Amount** ([`super::drain_amount::choose_drain_amount`]): `{user
//!   target, cadence, RNG}` + the aggregate scalar (affordability check
//!   only) → a drain amount that is provably not any reward subsum.
//! - **Select** ([`super::drain_select::select_for_drain`]): lineage-blind
//!   coin selection over the stripped `{output_id, amount, spendable_height}`
//!   vector.
//! - **Project** (this module): the single trust boundary. It is the **only**
//!   drain-path site that holds the persisted funding-output records
//!   (`PScanState.funding_outputs`) and reads their mint-lineage tag,
//!   arrival epoch, and arrival height. It projects those records into the
//!   two operands the guarded stages consume — the aggregate spendable
//!   scalar and the stripped candidate vector — mirroring the established
//!   "orchestrator prepares operands, downstream receives prepared values"
//!   seam (`claim_orchestrator.rs`). The amount and select modules never
//!   name the record or the lineage tag; this module does, and is
//!   deliberately excluded from the F-D1 M1 import-check arm.
//!
//! F-D2 (core-side half): the drain's `P`-balance surface is the **aggregate
//! scalar** ([`DrainBalance`]) — never a per-epoch/per-reward decomposition,
//! mirroring the principal `LedgerEngine::balance() -> BalanceSummary`
//! aggregate discipline. A UI built on this surface structurally cannot
//! pre-fill a reward-shaped figure because the decomposition never reaches
//! it. The wallet-flow default itself ("never seed a reward-derived amount")
//! lands in `shekyl-gui-wallet` — see the PR note.

use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

use super::drain_select::DrainCandidate;

/// The drain-path `P`-balance surface: a single aggregate spendable scalar
/// (F-D2 core-side). Carries no per-output/per-epoch breakdown by
/// construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainBalance {
    /// Sum of the provable (mature) `P` funding outputs at the reference
    /// height.
    pub spendable: AtomicUnits,
}

/// The prepared drain operands: the two projections the guarded stages read.
///
/// Minting this is the projection act — the record vector's `{lineage,
/// epoch, height}` are consumed here and do not survive into the operands.
pub(crate) struct DrainOperands {
    /// Aggregate spendable scalar (amount-stage affordability input; also the
    /// F-D2 balance surface).
    balance: DrainBalance,
    /// Stripped per-output candidates (select-stage input).
    candidates: Vec<DrainCandidate>,
}

impl DrainOperands {
    /// The aggregate scalar surface (F-D2).
    pub(crate) fn balance(&self) -> DrainBalance {
        self.balance
    }

    /// The stripped candidate vector (select-stage input).
    pub(crate) fn candidates(&self) -> &[DrainCandidate] {
        &self.candidates
    }
}

/// Project `P`'s persisted funding records into the drain operands, dropping
/// `{lineage, epoch, height}` and reducing to the mature (provable) subset.
///
/// Skeleton (F-D1 M1 arm lands first — real logic in the next commit).
pub(crate) fn project_drain_operands(
    _records: &[PFundingOutputRecord],
    _reference_height: BlockHeight,
) -> DrainOperands {
    DrainOperands {
        balance: DrainBalance {
            spendable: AtomicUnits::from_raw(0),
        },
        candidates: Vec::new(),
    }
}
