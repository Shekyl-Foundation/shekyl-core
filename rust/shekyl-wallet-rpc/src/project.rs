// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Domain → OpenAPI projections (accounting facts only; no secrets).

use shekyl_engine_core::PendingTx;
use shekyl_engine_core::RefreshSummary;
use shekyl_engine_state::TransferDetails;
use shekyl_scanner::BalanceSummary;
use shekyl_units::AtomicUnits;

use crate::types::{
    BuildPendingTxResult, GetBalanceResult, RefreshResult, TransferDirection, TransferState,
    TransferView,
};

/// Decimal string for OpenAPI `AtomicUnits`.
pub fn atomic_units_string(amount: AtomicUnits) -> String {
    amount.to_raw().to_string()
}

/// Map scanner balance into the locked OpenAPI balance shape.
///
/// `staked` / `claimable_rewards` stay `"0"` until Stage 3 stake methods
/// land (OpenAPI contract). `liquid` mirrors `unlocked` until staking
/// splits liquid from locked principal.
impl From<&BalanceSummary> for GetBalanceResult {
    fn from(b: &BalanceSummary) -> Self {
        let unlocked = atomic_units_string(b.unlocked);
        Self {
            liquid: unlocked.clone(),
            staked: "0".to_owned(),
            unlocked,
            claimable_rewards: "0".to_owned(),
            pending: atomic_units_string(b.awaiting_confirmation),
        }
    }
}

/// Stable transfer id: `{tx_hash_hex}:{internal_output_index}`.
pub fn transfer_id(td: &TransferDetails) -> String {
    format!("{}:{}", td.tx_hash, td.internal_output_index)
}

/// Confirmation / spend state of a ledger row.
///
/// Shared by [`transfer_view`] and the `get_transfers` filter so both agree on
/// how a row maps to [`TransferState`] without re-projecting the whole row.
pub fn transfer_state(td: &TransferDetails) -> TransferState {
    if td.spent {
        TransferState::Spent
    } else if td.awaiting_confirmation.is_some() {
        TransferState::Pending
    } else {
        TransferState::Confirmed
    }
}

/// Project a ledger transfer to the RPC view (no key material).
pub fn transfer_view(td: &TransferDetails) -> TransferView {
    TransferView {
        id: transfer_id(td),
        // Ledger rows are receive-side outputs; outgoing spends are
        // reflected as Spent state on the same row until a dedicated
        // outgoing history surface lands.
        direction: TransferDirection::Incoming,
        tx_hash: td.tx_hash.to_string(),
        amount: atomic_units_string(td.amount()),
        fee: "0".to_owned(),
        block_height: i64::try_from(td.block_height).unwrap_or(i64::MAX),
        state: transfer_state(td),
        spent_height: td
            .spent_height
            .map(|h| i64::try_from(h).unwrap_or(i64::MAX)),
    }
}

/// Project [`RefreshSummary`] + post-refresh ledger tip to OpenAPI.
pub fn refresh_result(summary: &RefreshSummary, synced_height: u64) -> RefreshResult {
    RefreshResult {
        blocks_processed: i64::try_from(summary.blocks_processed).unwrap_or(i64::MAX),
        transfers_detected: i64::try_from(summary.transfers_detected).unwrap_or(i64::MAX),
        synced_height: i64::try_from(synced_height).unwrap_or(i64::MAX),
        reorg_fork_height: summary
            .reorg
            .as_ref()
            .map(|r| i64::try_from(r.fork_height).unwrap_or(i64::MAX)),
    }
}

/// Project [`PendingTx`] to OpenAPI `BuildPendingTxResult`.
pub fn pending_tx_result(tx: &PendingTx) -> BuildPendingTxResult {
    BuildPendingTxResult {
        pending_tx_id: tx.id.raw().to_string(),
        built_at_height: i64::try_from(tx.built_at_height).unwrap_or(i64::MAX),
        built_at_tip_hash: hex::encode(tx.built_at_tip_hash),
        fee: atomic_units_string(tx.fee_atomic_units),
        content_gen: i64::try_from(tx.content_gen).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_units::AtomicUnits;

    #[test]
    fn balance_maps_unlocked_to_liquid() {
        let b = BalanceSummary {
            total: AtomicUnits::from_raw(100),
            unlocked: AtomicUnits::from_raw(40),
            locked_by_timelock: AtomicUnits::from_raw(10),
            frozen: AtomicUnits::ZERO,
            awaiting_confirmation: AtomicUnits::from_raw(5),
        };
        let r = GetBalanceResult::from(&b);
        assert_eq!(r.unlocked, "40");
        assert_eq!(r.liquid, "40");
        assert_eq!(r.pending, "5");
        assert_eq!(r.staked, "0");
        assert_eq!(r.claimable_rewards, "0");
    }
}
