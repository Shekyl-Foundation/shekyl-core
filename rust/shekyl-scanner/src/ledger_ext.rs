// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Scanner-side extension traits for [`LedgerBlock`] and [`LedgerIndexes`].
//!
//! The canonical [`TransferDetails`], [`LedgerBlock`], and
//! [`LedgerIndexes`] types live in `shekyl-engine-state` so they can be
//! shared with the wallet-file orchestrator without pulling in the
//! scanner's `Timelocked` / `RecoveredWalletOutput` / `BalanceSummary` /
//! `ClaimableInfo` universe.
//!
//! Everything that *does* require those scanner-only types lives here:
//!
//! - [`TransferDetailsExt::from_wallet_output`] — build a `TransferDetails` from
//!   the scanner's [`WalletOutput`], auto-populating staking metadata.
//! - [`LedgerIndexesExt::process_scanned_outputs`] — ingest a scanned block's
//!   `Timelocked<RecoveredWalletOutput>` into a `(LedgerBlock, LedgerIndexes)`
//!   pair atomically.
//! - [`LedgerBlockExt::balance`] — compute a [`BalanceSummary`] from the
//!   tracked transfers at a chain height.
//! - [`LedgerBlockExt::claimable_rewards_summary`] — compute per-staked-output
//!   claim estimates using the scanner's [`ClaimableInfo`] type and the
//!   accrual aggregate held in `LedgerIndexes::staker_pool`.
//!
//! Call sites must have these traits **in scope** for the
//! `TransferDetails::from_…` and `ledger.balance(…)` /
//! `indexes.process_scanned_outputs(&mut ledger, …)` call syntax to resolve.
//! The crate re-exports all three traits from `lib.rs` so
//! `use shekyl_scanner::{TransferDetailsExt, LedgerBlockExt, LedgerIndexesExt};`
//! is the canonical import.

use std::ops::Range;

use shekyl_engine_state::{LedgerBlock, LedgerIndexes, TransferDetails, SPENDABLE_AGE};

use crate::{
    balance::BalanceSummary, claim::ClaimableInfo, output::WalletOutput, scan::Timelocked,
};

/// Extension methods for [`TransferDetails`] that depend on scanner-only types.
pub trait TransferDetailsExt {
    /// Create a `TransferDetails` from a scanned [`WalletOutput`] at a given block height.
    ///
    /// Automatically populates staking fields if the output carries `StakingMeta`.
    /// `stake_lock_until` is computed as `block_height + tier_lock_blocks`. The
    /// M3b deterministic-handle pathway fields (`source_ciphertext`,
    /// `output_handle`) are left `None`; they are populated by the engine
    /// post-pass at `shekyl_engine_core::engine::merge::populate_engine_handle_fields`
    /// after the scanned block is merged into the ledger. The scanner does
    /// not hold the `view_secret` required by `derive_output_handle`, by
    /// design.
    fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self;
}

impl TransferDetailsExt for TransferDetails {
    fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self {
        let (staked, stake_tier, stake_lock_until) = match output.staking() {
            Some(meta) => {
                let lock_blocks = shekyl_staking::tiers::tier_by_id(meta.lock_tier)
                    .map(|t| t.lock_blocks)
                    .unwrap_or(0);
                (true, meta.lock_tier, block_height + lock_blocks)
            }
            None => (false, 0, 0),
        };
        TransferDetails {
            tx_hash: output.transaction(),
            internal_output_index: output.index_in_transaction(),
            global_output_index: output.index_on_blockchain(),
            block_height,
            key: output.key(),
            key_offset: output.key_offset(),
            commitment: output.commitment().clone(),
            subaddress: output.subaddress(),
            payment_id: output.payment_id(),
            spent: false,
            spent_height: None,
            key_image: None,
            staked,
            stake_tier,
            stake_lock_until,
            last_claimed_height: 0,
            combined_shared_secret: None,
            ho: None,
            y: None,
            z: None,
            k_amount: None,
            // M3b deterministic-handle pathway: populated by the
            // orchestrator-side post-pass in
            // `shekyl_engine_core::engine::merge` (commit 7), not by the
            // scanner itself. The scanner produces the handle's input
            // material (`tx_hash`, `internal_output_index`) but the
            // `view_secret` it would need to invoke
            // `derive_output_handle` lives in the engine, by design.
            // Leaving these as `None` here keeps `shekyl-scanner` free
            // of view-key access and lets the orchestrator populate the
            // fields after merging the per-block scan results into the
            // ledger.
            source_ciphertext: None,
            output_handle: None,
            eligible_height: block_height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }
}

/// Extension methods for [`LedgerIndexes`] that depend on scanner-only types.
pub trait LedgerIndexesExt {
    /// Process scanned outputs from a block, adding new transfers to the
    /// [`LedgerBlock`] and the lookup indexes maintained here.
    ///
    /// Populates the `TransferDetails.key_image` field from the
    /// [`RecoveredWalletOutput`](crate::scan::RecoveredWalletOutput) when
    /// a non-sentinel value is present, and advances the blockchain view
    /// by exactly one entry — even when the block contains zero outputs
    /// for this wallet. Per-output secrets (HKDF-derived `ho`, `y`, `z`,
    /// `k_amount`, `combined_shared_secret`) are intentionally not
    /// persisted in `TransferDetails` post-M3d; they are re-derived from
    /// `(view_secret, source_ciphertext)` by the engine at spend time.
    ///
    /// Returns the contiguous range of `ledger.transfers` indices into
    /// which accepted transfers were appended (`start..start + accepted`).
    /// Burning-bug duplicates dropped under the guard contract narrow
    /// the range. The range is the natural shape for the engine
    /// post-pass at `engine::merge::populate_engine_handle_fields` —
    /// it allows O(k) iteration over freshly appended transfers
    /// rather than O(n) scan of the full ledger. Propagates the inner
    /// [`LedgerIndexes::ingest_block`] return verbatim.
    fn process_scanned_outputs(
        &mut self,
        ledger: &mut LedgerBlock,
        block_height: u64,
        block_hash: [u8; 32],
        outputs: Timelocked,
    ) -> Range<usize>;
}

impl LedgerIndexesExt for LedgerIndexes {
    fn process_scanned_outputs(
        &mut self,
        ledger: &mut LedgerBlock,
        block_height: u64,
        block_hash: [u8; 32],
        outputs: Timelocked,
    ) -> Range<usize> {
        let outputs = outputs.into_inner();
        let mut batch = Vec::with_capacity(outputs.len());

        for output in outputs {
            let mut td = TransferDetails::from_wallet_output(output.wallet_output(), block_height);
            // The zero-bytes value is the test-fixture sentinel for "no
            // key image computed yet" (`RecoveredWalletOutput::new_for_test`).
            // The runtime scanner path always computes a real image, so a
            // zero here means we should leave `td.key_image = None` and let
            // an offline-derivation path (`set_key_image`) populate it later
            // — the same shape view-only wallets use. FOLLOWUPS: promote
            // `RecoveredWalletOutput.key_image` to `Option<KeyImage>` and
            // delete this sentinel comparison (V3.1).
            let ki = *output.key_image();
            if ki.as_bytes() != &[0u8; 32] {
                td.key_image = Some(ki);
            }
            batch.push(td);
        }

        self.ingest_block(ledger, block_height, block_hash, batch)
    }
}

/// Extension methods for [`LedgerBlock`] that depend on scanner-only types.
pub trait LedgerBlockExt {
    /// Compute a balance summary at the given chain height.
    fn balance(&self, current_height: u64) -> BalanceSummary;

    /// Compute a summary of claimable rewards for all staked outputs.
    ///
    /// `weight_fn` computes the tier-weighted stake for each output.
    /// `max_claim_range` is the protocol's `MAX_CLAIM_RANGE` constant.
    /// The accrual aggregate lives on [`LedgerIndexes::staker_pool`] and is
    /// rebuilt by scanner replay at wallet open — see the module-level
    /// docs on [`crate::ledger_indexes`](shekyl_engine_state::ledger_indexes)
    /// for why it is not persisted.
    fn claimable_rewards_summary<F>(
        &self,
        indexes: &LedgerIndexes,
        current_height: u64,
        weight_fn: F,
        max_claim_range: u64,
    ) -> Vec<(ClaimableInfo, u64)>
    where
        F: Fn(u64, u8) -> u64;
}

impl LedgerBlockExt for LedgerBlock {
    fn balance(&self, current_height: u64) -> BalanceSummary {
        BalanceSummary::compute(self.transfers(), current_height)
    }

    fn claimable_rewards_summary<F>(
        &self,
        indexes: &LedgerIndexes,
        current_height: u64,
        weight_fn: F,
        max_claim_range: u64,
    ) -> Vec<(ClaimableInfo, u64)>
    where
        F: Fn(u64, u8) -> u64,
    {
        let mut results = Vec::new();
        for (idx, td) in self.transfers().iter().enumerate() {
            if let Some(info) = ClaimableInfo::from_transfer(td, idx, current_height) {
                let weight = weight_fn(td.amount(), td.stake_tier);
                let (reward, _chunks) = indexes.staker_pool().estimate_reward_with_splitting(
                    info.from_height,
                    info.to_height,
                    weight,
                    max_claim_range,
                );
                results.push((info, reward));
            }
        }
        results
    }
}
