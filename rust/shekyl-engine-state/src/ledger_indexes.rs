// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Runtime-only indexes and aggregated state derived from chain replay.
//!
//! [`LedgerIndexes`] is the home for state that the scanner builds at
//! ingestion time, the wallet uses for O(1) lookups during signing,
//! and crucially is **not persisted** in [`LedgerBlock`]. Every field
//! is reconstructible from `LedgerBlock.transfers` plus daemon block
//! replay, and is rebuilt at `Engine::open*` time before any
//! mutation is permitted.
//!
//! See [`Self`] for the doc-comment that pins the unifying invariant.
//!
//! # Mutator surface
//!
//! Mutating methods that touch *both* [`LedgerBlock`] and [`LedgerIndexes`]
//! live here as `&mut self` methods that take `&mut LedgerBlock` as
//! their first argument. This is the "single ledger-mutation helper"
//! shape called for in `docs/V3_WALLET_DECISION_LOG.md` (`RuntimeWalletState`
//! audit, 2026-04-25): one call updates ledger state and indexes
//! atomically, and `debug_assert!`-driven invariant checks fire
//! after every mutation.
//!
//! Mutators that touch *only* the ledger (`freeze`, `thaw`,
//! `set_staking_info`, `update_claim_watermark`) live as inherent
//! methods on [`LedgerBlock`] in [`crate::ledger_block`] — there is no
//! reason to take a `&mut LedgerIndexes` borrow when the indexes are
//! never read.
//!
//! Read-only queries that touch only the ledger
//! (`unspent_transfers`, `staked_outputs`, `claimable_outputs`,
//! `spendable_outputs`, etc.) likewise live on [`LedgerBlock`]. The
//! single read-only query that needs indexes ([`Self::staker_pool`])
//! is exposed here.

use std::collections::HashMap;

use tracing::warn;
use zeroize::Zeroize;

use crate::{
    ledger_block::LedgerBlock,
    staker_pool::{AccrualRecord, StakerPoolState},
    transfer::TransferDetails,
};

/// Runtime-only state derived from chain replay. None of these fields
/// are persisted in [`LedgerBlock`]; all are rebuilt by replaying
/// scanned blocks at wallet open.
///
/// - `key_images`: lookup index from key-image bytes to the
///   [`LedgerBlock::transfers`] index.
/// - `pub_keys`: lookup index from output pubkey bytes to the
///   [`LedgerBlock::transfers`] index.
/// - `staker_pool`: aggregated stake-tier accrual state;
///   `LEDGER_BLOCK_VERSION = 1` deliberately omits persistence per
///   the staking design notes (see [`crate::ledger_block`] module
///   docstring).
///
/// Adding a field here means it MUST be reconstructible from
/// [`LedgerBlock`] + scanner replay. Adding a field that isn't
/// reconstructible — i.e., that needs persistence — is a
/// [`LedgerBlock`] change, not a [`LedgerIndexes`] change, and bumps
/// [`crate::ledger_block::LEDGER_BLOCK_VERSION`].
pub struct LedgerIndexes {
    /// Map from key image bytes to the [`LedgerBlock::transfers`]
    /// index of the enote that owns it. Populated as the scanner
    /// observes outputs and as `set_key_image` lands offline-derived
    /// images for view-only wallets.
    pub(crate) key_images: HashMap<[u8; 32], usize>,
    /// Map from output public-key bytes (compressed Edwards point)
    /// to the [`LedgerBlock::transfers`] index. Used by
    /// [`Self::ingest_block`] to detect the burning bug — a future
    /// scanned output reusing a pubkey we already know is dropped
    /// rather than admitted.
    pub(crate) pub_keys: HashMap<[u8; 32], usize>,
    /// Per-tier accrual aggregate used to estimate claim rewards.
    /// Rebuilt by replaying the scanned range at open time.
    pub(crate) staker_pool: StakerPoolState,
}

impl LedgerIndexes {
    /// An empty index set. Use this on a fresh wallet (no prior
    /// `LedgerBlock` to replay) or as the starting point for
    /// [`Self::rebuild_from_ledger`] before iterating transfers.
    pub fn empty() -> Self {
        Self {
            key_images: HashMap::new(),
            pub_keys: HashMap::new(),
            staker_pool: StakerPoolState::new(),
        }
    }

    /// Rebuild the lookup indexes from a freshly-loaded
    /// [`LedgerBlock`]. The `staker_pool` field is **not** rebuilt
    /// here — it is reconstructed by daemon-replay of the scanned
    /// range, owned by the scanner; this method handles only the
    /// O(1)-lookup half.
    ///
    /// On open: load `LedgerBlock` from disk, call
    /// `LedgerIndexes::rebuild_from_ledger(&ledger)`, then run the
    /// scanner replay to refill `staker_pool`. Both halves are
    /// idempotent under repeated calls.
    pub fn rebuild_from_ledger(ledger: &LedgerBlock) -> Self {
        let mut indexes = Self::empty();
        for (idx, td) in ledger.transfers.iter().enumerate() {
            let pub_key_bytes = td.key.compress().to_bytes();
            indexes.pub_keys.insert(pub_key_bytes, idx);
            if let Some(ki) = &td.key_image {
                if *ki != [0u8; 32] {
                    indexes.key_images.insert(*ki, idx);
                }
            }
        }
        indexes
    }

    /// Ingest the transfers for a single scanned block.
    ///
    /// The scanner converts the block's
    /// `Timelocked<RecoveredWalletOutput>` into a
    /// `Vec<TransferDetails>` (with all PQC fields populated) and
    /// hands it here. This method maintains the `pub_keys` /
    /// `key_images` indexes, advances `ledger.tip.synced_height`,
    /// and records `(block_height, block_hash)` in
    /// `ledger.reorg_blocks` exactly once — even when the block
    /// contains zero outputs for this wallet.
    ///
    /// Returns the number of transfers accepted (duplicates from the
    /// burning-bug guard are silently dropped with a `warn!`).
    pub fn ingest_block(
        &mut self,
        ledger: &mut LedgerBlock,
        block_height: u64,
        block_hash: [u8; 32],
        transfers: Vec<TransferDetails>,
    ) -> usize {
        let mut added = 0;
        for td in transfers {
            let pub_key_bytes = td.key.compress().to_bytes();
            if self.pub_keys.contains_key(&pub_key_bytes) {
                warn!(
                    tx = hex::encode(td.tx_hash),
                    output_idx = td.internal_output_index,
                    "duplicate output key detected (potential burning bug) -- skipping"
                );
                continue;
            }

            let idx = ledger.transfers.len();
            self.pub_keys.insert(pub_key_bytes, idx);
            if let Some(ki) = td.key_image {
                if ki != [0u8; 32] {
                    self.key_images.insert(ki, idx);
                }
            }
            ledger.transfers.push(td);
            added += 1;
        }

        ledger.tip.synced_height = block_height;
        ledger.tip.tip_hash = Some(block_hash);
        ledger.reorg_blocks.blocks.push((block_height, block_hash));

        debug_assert!(
            self.check_invariants(ledger).is_ok(),
            "invariant violated after ingest_block: {}",
            self.check_invariants(ledger).unwrap_err()
        );
        added
    }

    /// Mark an output as spent by its key image.
    ///
    /// Returns `true` if the key image was found and the output was
    /// marked spent.
    pub fn mark_spent(
        &self,
        ledger: &mut LedgerBlock,
        key_image: &[u8; 32],
        spent_height: u64,
    ) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            if let Some(td) = ledger.transfers.get_mut(idx) {
                td.spent = true;
                td.spent_height = Some(spent_height);
                debug_assert!(
                    self.check_invariants(ledger).is_ok(),
                    "invariant violated after mark_spent: {}",
                    self.check_invariants(ledger).unwrap_err()
                );
                return true;
            }
        }
        false
    }

    /// Reverse a spent mark for the given key images (rollback on
    /// finalize failure).
    ///
    /// After a signing round succeeds but the finalize step fails
    /// (daemon rejection, disk error, relay timeout), the outputs
    /// must be returned to the spendable pool. Without this, they
    /// become phantom-spent and the wallet's usable balance shrinks
    /// permanently.
    pub fn unmark_spent(&self, ledger: &mut LedgerBlock, key_images: &[[u8; 32]]) -> usize {
        let mut unmarked = 0;
        for ki in key_images {
            if let Some(&idx) = self.key_images.get(ki) {
                if let Some(td) = ledger.transfers.get_mut(idx) {
                    if td.spent {
                        td.spent = false;
                        td.spent_height = None;
                        unmarked += 1;
                    }
                }
            }
        }
        debug_assert!(
            self.check_invariants(ledger).is_ok(),
            "invariant violated after unmark_spent: {}",
            self.check_invariants(ledger).unwrap_err()
        );
        unmarked
    }

    /// Process incoming transaction inputs to detect spends of our
    /// outputs.
    pub fn detect_spends(
        &self,
        ledger: &mut LedgerBlock,
        block_height: u64,
        key_images: &[[u8; 32]],
    ) -> usize {
        let mut spent_count = 0;
        for ki in key_images {
            if self.mark_spent(ledger, ki, block_height) {
                spent_count += 1;
            }
        }
        spent_count
    }

    /// Set the key image for a transfer at the given index. No-op if
    /// the transfer already carries one (idempotent under view-only
    /// → full-view image rederivation).
    pub fn set_key_image(
        &mut self,
        ledger: &mut LedgerBlock,
        transfer_idx: usize,
        key_image: [u8; 32],
    ) {
        if let Some(td) = ledger.transfers.get_mut(transfer_idx) {
            if td.key_image.is_some() {
                return;
            }
            td.key_image = Some(key_image);
            self.key_images.insert(key_image, transfer_idx);
            debug_assert!(
                self.check_invariants(ledger).is_ok(),
                "invariant violated after set_key_image: {}",
                self.check_invariants(ledger).unwrap_err()
            );
        }
    }

    /// Freeze an output by its key image.
    pub fn freeze_by_key_image(&self, ledger: &mut LedgerBlock, key_image: &[u8; 32]) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            return ledger.freeze(idx);
        }
        false
    }

    /// Thaw an output by its key image.
    pub fn thaw_by_key_image(&self, ledger: &mut LedgerBlock, key_image: &[u8; 32]) -> bool {
        if let Some(&idx) = self.key_images.get(key_image) {
            return ledger.thaw(idx);
        }
        false
    }

    /// Handle a blockchain reorg by removing transfers at or above
    /// `fork_height` and rebuilding the lookup indexes from what
    /// survives.
    ///
    /// Drops the corresponding `(height, hash)` entries from
    /// `ledger.reorg_blocks`, rewinds `ledger.tip` to the highest
    /// remaining block, rebuilds `key_images` and `pub_keys`, and
    /// rolls the staker pool back to `fork_height`.
    pub fn handle_reorg(&mut self, ledger: &mut LedgerBlock, fork_height: u64) {
        for idx in (0..ledger.transfers.len()).rev() {
            if ledger.transfers[idx].block_height >= fork_height {
                ledger.transfers.remove(idx);
            }
        }

        ledger.reorg_blocks.blocks.retain(|(h, _)| *h < fork_height);

        match ledger.reorg_blocks.blocks.last() {
            Some(&(h, hash)) => {
                ledger.tip.synced_height = h;
                ledger.tip.tip_hash = Some(hash);
            }
            None => {
                ledger.tip.synced_height = 0;
                ledger.tip.tip_hash = None;
            }
        }

        self.key_images.clear();
        self.pub_keys.clear();
        for (idx, td) in ledger.transfers.iter().enumerate() {
            let pub_key_bytes = td.key.compress().to_bytes();
            self.pub_keys.insert(pub_key_bytes, idx);
            if let Some(ki) = &td.key_image {
                self.key_images.insert(*ki, idx);
            }
        }

        self.staker_pool.handle_reorg(fork_height);

        debug_assert!(
            self.check_invariants(ledger).is_ok(),
            "invariant violated after handle_reorg: {}",
            self.check_invariants(ledger).unwrap_err()
        );
    }

    /// Insert a staker pool accrual record. Touches only
    /// [`Self::staker_pool`]; does not borrow [`LedgerBlock`].
    pub fn insert_accrual(&mut self, height: u64, record: AccrualRecord) {
        self.staker_pool.insert(height, record);
    }

    /// Read access to the aggregated stake-tier accrual state.
    pub fn staker_pool(&self) -> &StakerPoolState {
        &self.staker_pool
    }

    /// Verify structural invariants of the indexes against the given
    /// [`LedgerBlock`].
    ///
    /// Returns `Ok(())` if all invariants hold, or `Err(description)`
    /// naming the first violated invariant. Called via
    /// `debug_assert!` after every mutation in debug builds, and
    /// explicitly in tests. The release-build version of these
    /// checks lives on [`crate::wallet_ledger::WalletLedger::check_invariants`]
    /// — those operate on the persisted bundle as a whole; this
    /// method is the live-mutation companion.
    pub fn check_invariants(&self, ledger: &LedgerBlock) -> Result<(), String> {
        // 1. Key-image index -> transfer consistency.
        for (ki, &idx) in &self.key_images {
            if idx >= ledger.transfers.len() {
                return Err(format!(
                    "key_images[{}] = {} out of bounds (len={})",
                    hex::encode(ki),
                    idx,
                    ledger.transfers.len()
                ));
            }
            match &ledger.transfers[idx].key_image {
                Some(td_ki) if td_ki == ki => {}
                Some(td_ki) => {
                    return Err(format!(
                        "key_images[{}] -> transfers[{}] but transfer has key_image={}",
                        hex::encode(ki),
                        idx,
                        hex::encode(td_ki)
                    ))
                }
                None => {
                    return Err(format!(
                        "key_images[{}] -> transfers[{}] but transfer has no key_image",
                        hex::encode(ki),
                        idx
                    ))
                }
            }
        }

        // 1b. Reverse: every transfer with a key image is indexed.
        let ki_count = ledger
            .transfers
            .iter()
            .filter(|td| td.key_image.is_some())
            .count();
        if self.key_images.len() != ki_count {
            return Err(format!(
                "key_images.len()={} but {} transfers have key_image.is_some()",
                self.key_images.len(),
                ki_count
            ));
        }

        // 2. Pub-key index -> transfer consistency.
        for (pk, &idx) in &self.pub_keys {
            if idx >= ledger.transfers.len() {
                return Err(format!(
                    "pub_keys[{}] = {} out of bounds (len={})",
                    hex::encode(pk),
                    idx,
                    ledger.transfers.len()
                ));
            }
            let td_pk = ledger.transfers[idx].key.compress().to_bytes();
            if &td_pk != pk {
                return Err(format!(
                    "pub_keys[{}] -> transfers[{}] but transfer has key={}",
                    hex::encode(pk),
                    idx,
                    hex::encode(td_pk)
                ));
            }
        }

        // 2b. Every transfer has its pub key indexed.
        if self.pub_keys.len() != ledger.transfers.len() {
            return Err(format!(
                "pub_keys.len()={} but transfers.len()={}",
                self.pub_keys.len(),
                ledger.transfers.len()
            ));
        }

        // 3. Spent-height consistency.
        for (i, td) in ledger.transfers.iter().enumerate() {
            if td.spent && td.spent_height.is_none() {
                return Err(format!("transfers[{i}] is spent but spent_height is None"));
            }
            if let (false, Some(h)) = (td.spent, td.spent_height) {
                return Err(format!(
                    "transfers[{i}] is not spent but spent_height is Some({h})"
                ));
            }
        }

        // 4. Reorg-window monotonicity.
        for window in ledger.reorg_blocks.blocks.windows(2) {
            if window[0].0 >= window[1].0 {
                return Err(format!(
                    "reorg_blocks not monotonic: height {} followed by {}",
                    window[0].0, window[1].0
                ));
            }
        }

        Ok(())
    }

    /// Explicit invariant check for callers that mutated
    /// [`LedgerBlock::transfers`] outside this helper (e.g. via a
    /// direct `&mut td` borrow obtained for a one-off field
    /// patch). Wrapped in `debug_assert!` so the cost is paid only
    /// in debug builds.
    pub fn check_after_mutation(&self, ledger: &LedgerBlock) {
        debug_assert!(
            self.check_invariants(ledger).is_ok(),
            "LedgerIndexes invariant violated after external mutation: {:?}",
            self.check_invariants(ledger).unwrap_err()
        );
    }
}

impl Default for LedgerIndexes {
    fn default() -> Self {
        Self::empty()
    }
}

impl Drop for LedgerIndexes {
    fn drop(&mut self) {
        for (mut ki, _) in self.key_images.drain() {
            ki.zeroize();
        }
        for (mut pk, _) in self.pub_keys.drain() {
            pk.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: invariant rebuild + mutator round-trips. Tests that exercise the
// scanner-side `process_scanned_outputs` extension live in shekyl-scanner's
// test module; this module covers only the pieces that don't need scanner
// types.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_oxide::primitives::Commitment;
    use zeroize::Zeroizing;

    use crate::{
        ledger_block::{BlockchainTip, LedgerBlock, ReorgBlocks},
        subaddress::SubaddressIndex,
        transfer::SPENDABLE_AGE,
    };

    fn mk_transfer(seed: u8, block_height: u64, key_image: Option<[u8; 32]>) -> TransferDetails {
        TransferDetails {
            tx_hash: [seed; 32],
            internal_output_index: u64::from(seed),
            global_output_index: u64::from(seed),
            block_height,
            key: ED25519_BASEPOINT_POINT * Scalar::from(u64::from(seed) + 1),
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1_000),
            subaddress: Some(SubaddressIndex::new(u32::from(seed).saturating_add(1))),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            combined_shared_secret: Some(Zeroizing::new([0; 64])),
            ho: Some(Zeroizing::new([0; 32])),
            y: Some(Zeroizing::new([0; 32])),
            z: Some(Zeroizing::new([0; 32])),
            k_amount: Some(Zeroizing::new([0; 32])),
            eligible_height: block_height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    #[test]
    fn rebuild_from_ledger_recovers_indexes() {
        let transfers = vec![
            mk_transfer(1, 100, Some([0xAA; 32])),
            mk_transfer(2, 110, None),
            mk_transfer(3, 120, Some([0xBB; 32])),
        ];
        let ledger = LedgerBlock::new(
            transfers,
            BlockchainTip::new(120, [0; 32]),
            ReorgBlocks::default(),
        );
        let indexes = LedgerIndexes::rebuild_from_ledger(&ledger);

        assert_eq!(indexes.key_images.len(), 2);
        assert_eq!(indexes.pub_keys.len(), 3);
        assert_eq!(indexes.key_images.get(&[0xAA; 32]).copied(), Some(0));
        assert_eq!(indexes.key_images.get(&[0xBB; 32]).copied(), Some(2));
        indexes
            .check_invariants(&ledger)
            .expect("rebuilt indexes are consistent");
    }

    #[test]
    fn ingest_block_advances_tip_and_indexes() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();

        let added = indexes.ingest_block(
            &mut ledger,
            100,
            [0xCC; 32],
            vec![mk_transfer(1, 100, Some([0xAA; 32]))],
        );
        assert_eq!(added, 1);
        assert_eq!(ledger.tip.synced_height, 100);
        assert_eq!(ledger.tip.tip_hash, Some([0xCC; 32]));
        assert_eq!(ledger.transfers.len(), 1);
        assert_eq!(indexes.key_images.get(&[0xAA; 32]).copied(), Some(0));
        indexes.check_invariants(&ledger).expect("after ingest");
    }

    #[test]
    fn ingest_block_rejects_burning_bug_duplicate() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();

        // Two transfers with the same `key` (same compressed bytes) —
        // the second is dropped under the burning-bug guard.
        let t1 = mk_transfer(1, 100, Some([0xAA; 32]));
        let t2 = mk_transfer(1, 110, Some([0xBB; 32]));
        let added = indexes.ingest_block(&mut ledger, 110, [0; 32], vec![t1, t2]);
        assert_eq!(added, 1);
        assert_eq!(ledger.transfers.len(), 1);
    }

    #[test]
    fn mark_unmark_spent_round_trips() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        indexes.ingest_block(
            &mut ledger,
            100,
            [0; 32],
            vec![mk_transfer(1, 100, Some([0xAA; 32]))],
        );

        assert!(indexes.mark_spent(&mut ledger, &[0xAA; 32], 200));
        assert!(ledger.transfers[0].spent);

        let unmarked = indexes.unmark_spent(&mut ledger, &[[0xAA; 32]]);
        assert_eq!(unmarked, 1);
        assert!(!ledger.transfers[0].spent);
    }

    #[test]
    fn handle_reorg_rebuilds_indexes_and_rewinds_tip() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        indexes.ingest_block(
            &mut ledger,
            100,
            [0xAA; 32],
            vec![mk_transfer(1, 100, Some([0x10; 32]))],
        );
        indexes.ingest_block(
            &mut ledger,
            200,
            [0xBB; 32],
            vec![mk_transfer(2, 200, Some([0x20; 32]))],
        );
        assert_eq!(ledger.transfers.len(), 2);

        indexes.handle_reorg(&mut ledger, 200);
        assert_eq!(ledger.transfers.len(), 1);
        assert_eq!(ledger.tip.synced_height, 100);
        assert_eq!(ledger.tip.tip_hash, Some([0xAA; 32]));
        assert!(indexes.key_images.contains_key(&[0x10; 32]));
        assert!(!indexes.key_images.contains_key(&[0x20; 32]));
    }

    #[test]
    fn set_key_image_is_idempotent() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        indexes.ingest_block(&mut ledger, 100, [0; 32], vec![mk_transfer(1, 100, None)]);

        indexes.set_key_image(&mut ledger, 0, [0xAA; 32]);
        assert_eq!(ledger.transfers[0].key_image, Some([0xAA; 32]));
        // Second call is a no-op.
        indexes.set_key_image(&mut ledger, 0, [0xBB; 32]);
        assert_eq!(ledger.transfers[0].key_image, Some([0xAA; 32]));
    }
}
