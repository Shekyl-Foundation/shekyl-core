// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Ledger block — the transfers cache + blockchain tip + reorg window
//! used by the scanner to resume after a restart.
//!
//! This is the first of four typed blocks that together make up the
//! `.wallet` side of the two-file wallet envelope (commits 2d–2g):
//!
//! * [`LedgerBlock`] — this module: on-chain-derived scanner state.
//! * `BookkeepingBlock` (2e) — subaddress registry, labels, address book,
//!   account tags.
//! * `TxMetaBlock` (2f) — per-transaction keys, notes, attributes, and
//!   the scanned-pool cache.
//! * `SyncStateBlock` (2g) — unconfirmed / confirmed tx tracking plus
//!   background-sync view, aggregated into a top-level `WalletLedger`
//!   along with bundle-shape versioning.
//!
//! # Wire format
//!
//! Postcard (`serde`-compatible binary format). All sub-types derive
//! `Serialize`/`Deserialize` and produce compact, byte-stable output;
//! large homogeneous fields (`transfers`, `reorg_blocks.blocks`) were
//! the deciding factor for picking postcard over JSON per
//! `.cursor/rules/42-serialization-policy.mdc` (added in 2n).
//!
//! # Secret discipline
//!
//! [`TransferDetails`] already wraps its HKDF-derived scalars in
//! [`zeroize::Zeroizing`] and refuses to implement `Clone` to prevent
//! silent duplication of those secrets; the orchestrator that owns
//! the decrypted ledger bytes (commit 2h) is responsible for holding
//! them in a `Zeroizing<Vec<u8>>` until the block has been deserialized.
//!
//! # What is *not* in this block
//!
//! * `StakerPoolState` — the scanner's per-block accrual cache is
//!   explicitly **not** persisted in `LEDGER_BLOCK_VERSION = 1`. The
//!   daemon RPC can rebuild it by replaying the scan range, and
//!   persisting it would couple the wallet's ledger schema to the
//!   staking accounting format. If a future UX benchmark shows that
//!   the RPC-refill cost is unacceptable, a follow-up block version
//!   can add it without migrating existing wallets (the version gate
//!   will refuse a 1-vs-2 mismatch, forcing users to rescan once).

use serde::{Deserialize, Serialize};

use crate::{error::WalletLedgerError, subaddress::SubaddressIndex, transfer::TransferDetails};

/// Schema version of the ledger block. V3.0 ships version `1`. Any
/// field addition / removal / renaming inside the block bumps this;
/// loads that see a different version refuse rather than migrate.
pub const LEDGER_BLOCK_VERSION: u32 = 1;

/// Maximum number of `(height, hash)` pairs the scanner should keep in
/// [`ReorgBlocks`]. The value is informational — the persistence layer
/// does not truncate; it is enforced by the scanner before serializing.
/// Pinned here so both the producer and the consumer read the same
/// constant.
///
/// Sized to comfortably exceed the deepest reorg ever observed on
/// Monero mainnet (~6) while staying below Shekyl V3's conservative
/// scan-safety `max_reorg_depth` default (10) with headroom.
pub const DEFAULT_REORG_BLOCKS_CAPACITY: usize = 32;

/// Pointer to the most recently scanned block — "where the wallet is"
/// on the chain.
///
/// The scanner advances this every block, whether the block contained
/// wallet-relevant outputs or not. On reload, it is cross-checked
/// against `reorg_blocks.last()` for consistency (a mismatch indicates
/// disk corruption, not a reorg, and is handled by the orchestrator).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct BlockchainTip {
    /// Highest block height the scanner has processed.
    pub synced_height: u64,
    /// Block hash at `synced_height`. `None` on a fresh wallet that
    /// has never ingested a block (the Rust wallet's bootstrap state
    /// — `synced_height = 0` and no tip hash is known yet).
    pub tip_hash: Option<[u8; 32]>,
}

impl BlockchainTip {
    /// Construct a tip from a height + hash. Use
    /// [`BlockchainTip::default`] for the unscanned state.
    pub fn new(synced_height: u64, tip_hash: [u8; 32]) -> Self {
        Self {
            synced_height,
            tip_hash: Some(tip_hash),
        }
    }

    /// `true` when the wallet has never scanned any block.
    pub fn is_unscanned(&self) -> bool {
        self.synced_height == 0 && self.tip_hash.is_none()
    }
}

/// Rolling window of `(height, block_hash)` pairs used for reorg
/// detection. Sorted strictly ascending by height; duplicates at a
/// given height are *not* allowed.
///
/// The scanner trims this to [`DEFAULT_REORG_BLOCKS_CAPACITY`] entries
/// before serializing; this module does not enforce the cap at
/// deserialize-time so that a wallet written by a future scanner with
/// a larger window still loads under this block version. Monotonicity
/// is likewise the scanner's invariant — `LedgerBlock::check_version`
/// verifies only the version field, so a corrupt or non-monotonic
/// sequence will be caught by the runtime's `check_invariants`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct ReorgBlocks {
    /// The `(height, block_hash)` pairs. Strictly ascending by height.
    pub blocks: Vec<(u64, [u8; 32])>,
}

impl ReorgBlocks {
    /// The highest `(height, hash)` pair, or `None` if empty.
    pub fn last(&self) -> Option<&(u64, [u8; 32])> {
        self.blocks.last()
    }

    /// Number of blocks in the window.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// `true` when no blocks have been recorded.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// The ledger block. Scanner-derived on-chain state that persists to
/// the `.wallet` file. See module docs for scope, versioning, wire
/// format, and secret discipline.
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct LedgerBlock {
    /// Per-block schema version. Always [`LEDGER_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Scanned transfers owned by this wallet. See
    /// [`crate::transfer::TransferDetails`] for the per-entry shape;
    /// note that `TransferDetails` is deliberately **not** `Clone` —
    /// construct a `LedgerBlock` by moving transfers in.
    pub transfers: Vec<TransferDetails>,

    /// Current scan pointer.
    pub tip: BlockchainTip,

    /// Rolling `(height, hash)` window used by the scanner for reorg
    /// detection. The scanner caps this at
    /// [`DEFAULT_REORG_BLOCKS_CAPACITY`] before write.
    pub reorg_blocks: ReorgBlocks,
}

impl LedgerBlock {
    /// Construct a fresh, empty ledger block at the current version.
    pub fn empty() -> Self {
        Self {
            block_version: LEDGER_BLOCK_VERSION,
            transfers: Vec::new(),
            tip: BlockchainTip::default(),
            reorg_blocks: ReorgBlocks::default(),
        }
    }

    /// Assemble a `LedgerBlock` from its parts. Moves `transfers` in
    /// because [`TransferDetails`] is not `Clone` — a caller holding a
    /// `&RuntimeWalletState` must therefore drive a snapshot through
    /// serialization (see commit 2h's orchestrator for the pattern).
    pub fn new(
        transfers: Vec<TransferDetails>,
        tip: BlockchainTip,
        reorg_blocks: ReorgBlocks,
    ) -> Self {
        Self {
            block_version: LEDGER_BLOCK_VERSION,
            transfers,
            tip,
            reorg_blocks,
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`LedgerBlock::to_postcard_bytes`]. Refuses any version mismatch.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so the `WalletLedger` aggregator (commit 2g) can
    /// fan out the same check across every block in the bundle.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.block_version != LEDGER_BLOCK_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "ledger",
                file: self.block_version,
                binary: LEDGER_BLOCK_VERSION,
            });
        }
        Ok(())
    }

    // -- Read-only queries (moved from RuntimeWalletState) -----------------

    /// The current synced height (== `tip.synced_height`).
    pub fn height(&self) -> u64 {
        self.tip.synced_height
    }

    /// All tracked transfers as a slice.
    pub fn transfers(&self) -> &[TransferDetails] {
        &self.transfers
    }

    /// Number of tracked transfers.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Get the stored block hash for the given height, if it is
    /// inside the reorg window.
    pub fn block_hash_at(&self, height: u64) -> Option<&[u8; 32]> {
        self.reorg_blocks
            .blocks
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| hash)
    }

    /// Get staked outputs that have unclaimed reward backlog.
    pub fn claimable_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.has_claimable_rewards(current_height))
            .collect()
    }

    /// Get staked outputs that are eligible for unstaking (matured,
    /// unspent).
    pub fn unstakeable_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_unstakeable(current_height))
            .collect()
    }

    /// Get unspent, unfrozen transfers.
    pub fn unspent_transfers(&self) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| !td.spent && !td.frozen)
            .collect()
    }

    /// Get staked outputs (all states).
    pub fn staked_outputs(&self) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.staked && !td.spent)
            .collect()
    }

    /// Get matured staked outputs (lock period expired, still
    /// unspent).
    pub fn matured_staked_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_matured_stake(current_height) && !td.spent)
            .collect()
    }

    /// Get locked staked outputs (still within lock period).
    pub fn locked_staked_outputs(&self, current_height: u64) -> Vec<&TransferDetails> {
        self.transfers
            .iter()
            .filter(|td| td.is_locked_stake(current_height) && !td.spent)
            .collect()
    }

    /// Get spendable outputs with optional subaddress / amount
    /// filters.
    ///
    /// Only returns outputs where `current_height >= eligible_height`
    /// — the daemon has no curve-tree path for immature outputs, so
    /// attempting to spend them would fail at FCMP++ proof generation.
    pub fn spendable_outputs(
        &self,
        current_height: u64,
        subaddress: Option<SubaddressIndex>,
        min_amount: Option<u64>,
    ) -> Vec<(usize, &TransferDetails)> {
        self.transfers
            .iter()
            .enumerate()
            .filter(|(_, td)| {
                if !td.is_spendable(current_height) {
                    return false;
                }
                if let Some(sub) = subaddress {
                    if td.subaddress != Some(sub) {
                        return false;
                    }
                }
                if let Some(min) = min_amount {
                    if td.amount() < min {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    // -- Mutators on transfer-only state ------------------------------------

    /// Get a mutable reference to a transfer by index. The caller is
    /// responsible for invoking
    /// [`crate::ledger_indexes::LedgerIndexes::check_after_mutation`]
    /// once finished if the mutation could disturb an indexed field
    /// (`key`, `key_image`).
    pub fn transfer_mut(&mut self, idx: usize) -> Option<&mut TransferDetails> {
        self.transfers.get_mut(idx)
    }

    /// Set staking info for a transfer at the given index.
    pub fn set_staking_info(&mut self, transfer_idx: usize, tier: u8) {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.staked = true;
            td.stake_tier = tier;
            let lock_blocks = shekyl_staking::tiers::tier_by_id(tier)
                .map(|t| t.lock_blocks)
                .unwrap_or(0);
            td.stake_lock_until = td.block_height + lock_blocks;
        }
    }

    /// Update the claim watermark for a staked output identified by
    /// global output index. No-op if no staked output matches.
    pub fn update_claim_watermark(&mut self, global_output_index: u64, to_height: u64) {
        for td in &mut self.transfers {
            if td.staked && td.global_output_index == global_output_index {
                td.last_claimed_height = to_height;
                return;
            }
        }
    }

    /// Freeze an output by its [`Self::transfers`] index, preventing
    /// it from being selected for spending.
    pub fn freeze(&mut self, transfer_idx: usize) -> bool {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.frozen = true;
            return true;
        }
        false
    }

    /// Thaw a frozen output by its [`Self::transfers`] index.
    pub fn thaw(&mut self, transfer_idx: usize) -> bool {
        if let Some(td) = self.transfers.get_mut(transfer_idx) {
            td.frozen = false;
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Tests: byte-stable postcard round-trips, version refusal, and proptests
// that generate arbitrary tip / reorg windows. `TransferDetails` does not
// derive `PartialEq`, so transfer-bearing round-trips assert byte-stability
// (serialize -> bytes1 -> deserialize -> serialize -> bytes2; bytes1 ==
// bytes2) rather than value equality.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use proptest::prelude::*;
    use shekyl_oxide::primitives::Commitment;
    use zeroize::Zeroizing;

    use crate::{payment_id::PaymentId, subaddress::SubaddressIndex, transfer::SPENDABLE_AGE};

    fn sample_transfer(seed: u8) -> TransferDetails {
        TransferDetails {
            tx_hash: [seed; 32],
            internal_output_index: u64::from(seed),
            global_output_index: 1_000 + u64::from(seed),
            block_height: 100,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1_000_000 + u64::from(seed)),
            subaddress: Some(SubaddressIndex::new(u32::from(seed))),
            payment_id: Some(PaymentId([seed; 8])),
            spent: false,
            spent_height: None,
            key_image: Some([seed ^ 0xFF; 32]),
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            combined_shared_secret: Some(Zeroizing::new([seed.wrapping_add(1); 64])),
            ho: Some(Zeroizing::new([seed.wrapping_add(2); 32])),
            y: Some(Zeroizing::new([seed.wrapping_add(3); 32])),
            z: Some(Zeroizing::new([seed.wrapping_add(4); 32])),
            k_amount: Some(Zeroizing::new([seed.wrapping_add(5); 32])),
            eligible_height: 100 + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
        }
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = LedgerBlock::empty();
        assert_eq!(b.block_version, LEDGER_BLOCK_VERSION);
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = LedgerBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back.block_version, LEDGER_BLOCK_VERSION);
        assert!(back.transfers.is_empty());
        assert_eq!(back.tip, BlockchainTip::default());
        assert_eq!(back.reorg_blocks.blocks, Vec::<(u64, [u8; 32])>::new());
    }

    #[test]
    fn populated_block_is_byte_stable() {
        let tip = BlockchainTip::new(500, [0xAA; 32]);
        let reorg = ReorgBlocks {
            blocks: vec![(498, [0x10; 32]), (499, [0x20; 32]), (500, [0xAA; 32])],
        };
        let transfers = vec![sample_transfer(1), sample_transfer(2), sample_transfer(3)];

        let block = LedgerBlock::new(transfers, tip.clone(), reorg.clone());
        let bytes1 = block.to_postcard_bytes().expect("serialize1");
        let round = LedgerBlock::from_postcard_bytes(&bytes1).expect("deserialize");
        assert_eq!(round.block_version, LEDGER_BLOCK_VERSION);
        assert_eq!(round.tip, tip);
        assert_eq!(round.reorg_blocks, reorg);
        assert_eq!(round.transfers.len(), 3);
        let bytes2 = round.to_postcard_bytes().expect("serialize2");
        assert_eq!(bytes1, bytes2, "postcard encoding must be byte-stable");
    }

    #[test]
    fn populated_block_transfers_roundtrip_field_by_field() {
        let transfers = vec![sample_transfer(7), sample_transfer(8)];
        let block = LedgerBlock::new(
            transfers,
            BlockchainTip::new(10, [1u8; 32]),
            ReorgBlocks::default(),
        );

        // Snapshot representative fields *before* round-tripping. The
        // originals are then consumed by `to_postcard_bytes`.
        let originals: Vec<_> = block
            .transfers
            .iter()
            .map(|t| {
                (
                    t.tx_hash,
                    t.internal_output_index,
                    t.global_output_index,
                    t.amount(),
                    t.key_image,
                    t.ho.as_deref().copied(),
                    t.y.as_deref().copied(),
                    t.z.as_deref().copied(),
                    t.k_amount.as_deref().copied(),
                    t.combined_shared_secret.as_deref().copied(),
                )
            })
            .collect();

        let bytes = block.to_postcard_bytes().expect("serialize");
        let back = LedgerBlock::from_postcard_bytes(&bytes).expect("deserialize");

        assert_eq!(back.transfers.len(), originals.len());
        for (orig, t) in originals.iter().zip(back.transfers.iter()) {
            assert_eq!(&t.tx_hash, &orig.0);
            assert_eq!(t.internal_output_index, orig.1);
            assert_eq!(t.global_output_index, orig.2);
            assert_eq!(t.amount(), orig.3);
            assert_eq!(t.key_image, orig.4);
            assert_eq!(t.ho.as_deref().copied(), orig.5);
            assert_eq!(t.y.as_deref().copied(), orig.6);
            assert_eq!(t.z.as_deref().copied(), orig.7);
            assert_eq!(t.k_amount.as_deref().copied(), orig.8);
            assert_eq!(t.combined_shared_secret.as_deref().copied(), orig.9);
        }
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut b = LedgerBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match LedgerBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "ledger");
                assert_eq!(file, 999);
                assert_eq!(binary, LEDGER_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let b = LedgerBlock::new(
            vec![sample_transfer(1)],
            BlockchainTip::new(7, [7; 32]),
            ReorgBlocks {
                blocks: vec![(7, [7; 32])],
            },
        );
        let bytes = b.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        assert!(matches!(
            LedgerBlock::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        ));
    }

    #[test]
    fn tip_unscanned_predicate() {
        assert!(BlockchainTip::default().is_unscanned());
        assert!(!BlockchainTip::new(1, [0; 32]).is_unscanned());
    }

    proptest! {
        // Arbitrary tip + reorg window with zero transfers — exercises the
        // envelope shape independent of the (non-`PartialEq`, non-`Clone`)
        // `TransferDetails` payload.
        #[test]
        fn tip_and_reorg_window_round_trip(
            synced in any::<u64>(),
            tip_hash in any::<Option<[u8; 32]>>(),
            reorg in proptest::collection::vec((any::<u64>(), any::<[u8; 32]>()), 0..16),
        ) {
            let block = LedgerBlock::new(
                Vec::new(),
                BlockchainTip {
                    synced_height: synced,
                    tip_hash,
                },
                ReorgBlocks { blocks: reorg.clone() },
            );
            let bytes = block.to_postcard_bytes().expect("serialize");
            let back = LedgerBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(back.block_version, LEDGER_BLOCK_VERSION);
            prop_assert_eq!(back.tip.synced_height, synced);
            prop_assert_eq!(back.tip.tip_hash, tip_hash);
            prop_assert_eq!(back.reorg_blocks.blocks, reorg);
            prop_assert!(back.transfers.is_empty());
        }

        // Byte-stability under a transfer payload: we cannot `PartialEq`
        // `TransferDetails`, but we can assert that re-serializing the
        // deserialized block yields exactly the same bytes. This pins the
        // wire format for the combined (transfers + tip + reorg) shape.
        #[test]
        fn byte_stability_under_transfers(
            n in 0u8..4,
            synced in any::<u64>(),
            tip_hash in any::<Option<[u8; 32]>>(),
        ) {
            let transfers = (0..n).map(sample_transfer).collect();
            let block = LedgerBlock::new(
                transfers,
                BlockchainTip { synced_height: synced, tip_hash },
                ReorgBlocks::default(),
            );
            let bytes1 = block.to_postcard_bytes().expect("serialize1");
            let round = LedgerBlock::from_postcard_bytes(&bytes1).expect("deserialize");
            let bytes2 = round.to_postcard_bytes().expect("serialize2");
            prop_assert_eq!(bytes1, bytes2);
        }

        // A non-LEDGER_BLOCK_VERSION field refuses on load for any value
        // that differs from the binary's version constant.
        #[test]
        fn any_wrong_version_is_refused(bad in any::<u32>().prop_filter(
            "must differ from current version",
            |v| *v != LEDGER_BLOCK_VERSION,
        )) {
            let mut b = LedgerBlock::empty();
            b.block_version = bad;
            let bytes = b.to_postcard_bytes().expect("serialize");
            let err = LedgerBlock::from_postcard_bytes(&bytes).unwrap_err();
            let is_version_err = matches!(
                err,
                WalletLedgerError::UnsupportedBlockVersion { .. }
            );
            prop_assert!(is_version_err, "expected UnsupportedBlockVersion");
        }
    }
}
