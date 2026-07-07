// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Scanner-side extension traits for [`LedgerBlock`] and [`LedgerIndexes`].
//!
//! The canonical [`TransferDetails`], [`LedgerBlock`], and
//! [`LedgerIndexes`] types live in `shekyl-engine-state` so they can be
//! shared with the wallet-file orchestrator without pulling in the
//! scanner's `Timelocked` / `RecoveredWalletOutput` / `BalanceSummary`
//! universe.
//!
//! Everything that *does* require those scanner-only types lives here:
//!
//! - [`TransferDetailsExt::from_wallet_output`] — build a `TransferDetails` from
//!   the scanner's [`WalletOutput`].
//! - [`LedgerIndexesExt::process_scanned_outputs`] — ingest a scanned block's
//!   `Timelocked<RecoveredWalletOutput>` into a `(LedgerBlock, LedgerIndexes)`
//!   pair atomically.
//! - [`LedgerBlockExt::balance`] — compute a [`BalanceSummary`] from the
//!   tracked transfers at a chain height.
//!
//! Call sites must have these traits **in scope** for the
//! `TransferDetails::from_…` and `ledger.balance(…)` /
//! `indexes.process_scanned_outputs(&mut ledger, …)` call syntax to resolve.
//! The crate re-exports all three traits from `lib.rs` so
//! `use shekyl_scanner::{TransferDetailsExt, LedgerBlockExt, LedgerIndexesExt};`
//! is the canonical import.

use std::ops::Range;

use shekyl_engine_state::{
    LedgerBlock, LedgerIndexes, ReceiveAttribution, TransferDetails, SPENDABLE_AGE,
};
use shekyl_types::Timelock;

use crate::{balance::BalanceSummary, output::WalletOutput, scan::Timelocked};

/// Extension methods for [`TransferDetails`] that depend on scanner-only types.
pub trait TransferDetailsExt {
    /// Create a `TransferDetails` from a scanned [`WalletOutput`] at a given block height.
    ///
    /// The M3b deterministic-handle pathway fields (`source_ciphertext`,
    /// `output_handle`) are left `None`; they are populated by the engine
    /// post-pass at `shekyl_engine_core::engine::merge::populate_engine_handle_fields`
    /// after the scanned block is merged into the ledger. The scanner does
    /// not hold the `view_secret` required by `derive_output_handle`, by
    /// design.
    fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self;
}

/// The absolute block height an output's additional timelock unlocks at, for
/// the `eligible_height` floor (X5). [`Timelock`] is block-height-only, so this is
/// exactly its raw unlock value: the block height for [`Timelock::Block`], `0` for
/// [`Timelock::None`]. (The CryptoNote timestamp form is not representable.)
fn additional_timelock_block(timelock: Timelock) -> u64 {
    timelock.to_unlock_raw()
}

impl TransferDetailsExt for TransferDetails {
    fn from_wallet_output(output: &WalletOutput, block_height: u64) -> Self {
        TransferDetails {
            tx_hash: shekyl_types::TxHash::from_bytes(output.transaction()),
            internal_output_index: output.index_in_transaction(),
            global_output_index: output.index_on_blockchain(),
            block_height,
            key: output.key(),
            key_offset: output.key_offset(),
            commitment: output.commitment().clone(),
            payment_id: output.payment_id(),
            spent: false,
            spent_height: None,
            key_image: None,
            awaiting_confirmation: None,
            // M3b deterministic-handle pathway: populated by the
            // orchestrator-side post-pass in
            // `shekyl_engine_core::engine::merge::populate_engine_handle_fields`,
            // not by the scanner itself. The scanner produces the
            // handle's input material (`tx_hash`,
            // `internal_output_index`) but the `view_secret` it would
            // need to invoke `derive_output_handle` lives in the
            // engine, by design. Leaving these as `None` here keeps
            // `shekyl-scanner` free of view-key access and lets the
            // orchestrator populate the fields after merging the
            // per-block scan results into the ledger.
            //
            // Post-M3d (per `STAGE_1_PR_3_M3D_PREFLIGHT.md` §3.3),
            // the five legacy per-output secret fields
            // (`combined_shared_secret`, `ho`, `y`, `z`, `k_amount`)
            // were removed in the schema migration; `source_ciphertext`
            // and `output_handle` are the only inputs the engine needs
            // to re-derive the spend material at signing time. Other
            // `Option`-valued fields on `TransferDetails`
            // (`payment_id`, `spent_height`, `key_image`,
            // `fcmp_precomputed_path`) exist for unrelated reasons and
            // are unaffected by this construction site.
            source_ciphertext: None,
            output_handle: None,
            // X5 (CT-5c): the curve tree inserts an output at the *maximum* of
            // its spendable-age maturity and its additional timelock (e.g. the
            // block-based coinbase lock, which matures at +60, not the flat
            // +SPENDABLE_AGE). `eligible_height` must agree with that insertion
            // height — otherwise selection would treat a coinbase as spendable
            // at +SPENDABLE_AGE while its leaf is absent from the tree until
            // the coinbase lock expires, attempting an unprovable spend.
            eligible_height: (block_height + SPENDABLE_AGE)
                .max(additional_timelock_block(output.additional_timelock())),
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: ReceiveAttribution::default(),
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
}

impl LedgerBlockExt for LedgerBlock {
    fn balance(&self, current_height: u64) -> BalanceSummary {
        BalanceSummary::compute(self.transfers(), current_height)
    }
}

#[cfg(test)]
mod x5_eligible_height_tests {
    use super::*;
    use crate::output::WalletOutput;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_curve_primitives::Commitment;
    use shekyl_types::{BlockHeight, Timelock};

    fn dummy_output() -> WalletOutput {
        let key = &Scalar::from_bytes_mod_order([7u8; 32]) * ED25519_BASEPOINT_TABLE;
        WalletOutput::new_for_test(
            [0x11; 32],
            0,
            1,
            key,
            Scalar::ZERO,
            Commitment::new(Scalar::ONE, 1_000),
        )
    }

    /// Baseline: no timelock → `eligible_height = block + SPENDABLE_AGE`.
    #[test]
    fn eligible_height_baseline_is_spendable_age() {
        let td = TransferDetails::from_wallet_output(&dummy_output(), 100);
        assert_eq!(td.eligible_height, 100 + SPENDABLE_AGE);
    }

    /// X5 core: a block-based additional timelock (the coinbase +60 lock) floors
    /// `eligible_height` above the flat `+SPENDABLE_AGE`, so selection agrees
    /// with the tree's coinbase insertion height instead of treating the output
    /// as spendable at +SPENDABLE_AGE while its leaf is still absent.
    #[test]
    fn eligible_height_respects_block_timelock() {
        let out =
            dummy_output().with_additional_timelock(Timelock::Block(BlockHeight::from_raw(160)));
        let td = TransferDetails::from_wallet_output(&out, 100);
        assert_eq!(
            td.eligible_height, 160,
            "block timelock (160) floors eligible_height above block + SPENDABLE_AGE (110)"
        );
    }

    // (The former `eligible_height_ignores_time_timelock` test is retired: the
    // CryptoNote timestamp-form `Timelock::Time` is no longer representable —
    // `Timelock` is block-height-only — so there is nothing to ignore. The
    // former stake-lock floor test is retired with the claim-era staking
    // sweep: TransferDetails no longer carries stake fields.)
}
