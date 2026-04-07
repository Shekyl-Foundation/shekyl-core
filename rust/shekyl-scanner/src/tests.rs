// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for scanner staking detection, claim tracking, and wallet state.

#[cfg(test)]
pub(crate) mod staking {
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE};
    use shekyl_oxide::{primitives::Commitment, transaction::StakingMeta};

    use crate::{
        output::*,
        transfer::TransferDetails,
        wallet_state::WalletState,
        scan::Timelocked,
        claim::ClaimableInfo,
    };

    fn tier_lock(tier: u8) -> u64 {
        shekyl_staking::tiers::tier_by_id(tier).unwrap().lock_blocks
    }

    /// Generate a unique EdwardsPoint from a u64 seed (deterministic, distinct per seed).
    fn unique_point(seed: u64) -> curve25519_dalek::EdwardsPoint {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let scalar = Scalar::from_bytes_mod_order(bytes);
        &scalar * ED25519_BASEPOINT_TABLE
    }

    pub(crate) fn make_wallet_output(
        tx_hash: [u8; 32],
        index: u64,
        global_index: u64,
        amount: u64,
        staking: Option<StakingMeta>,
    ) -> WalletOutput {
        WalletOutput {
            absolute_id: AbsoluteId { transaction: tx_hash, index_in_transaction: index },
            relative_id: RelativeId { index_on_blockchain: global_index },
            data: OutputData {
                key: unique_point(global_index),
                key_offset: Scalar::ZERO,
                commitment: Commitment { mask: Scalar::ONE, amount },
            },
            metadata: Metadata {
                additional_timelock: shekyl_oxide::transaction::Timelock::None,
                subaddress: None,
                payment_id: None,
                arbitrary_data: vec![],
            },
            staking,
        }
    }

    fn make_timelocked(outputs: Vec<WalletOutput>) -> Timelocked {
        Timelocked(outputs)
    }

    // ── Staking detection ──

    #[test]
    fn from_wallet_output_detects_staked() {
        let output = make_wallet_output(
            [1; 32], 0, 100, 5_000_000_000,
            Some(StakingMeta { lock_tier: 2 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);
        assert!(td.staked);
        assert_eq!(td.stake_tier, 2);
        assert_eq!(td.stake_lock_until, 1000 + tier_lock(2));
        assert_eq!(td.last_claimed_height, 0);
    }

    #[test]
    fn from_wallet_output_non_staked() {
        let output = make_wallet_output([2; 32], 0, 101, 1_000_000_000, None);
        let td = TransferDetails::from_wallet_output(&output, 1000);
        assert!(!td.staked);
        assert_eq!(td.stake_tier, 0);
        assert_eq!(td.stake_lock_until, 0);
    }

    // ── is_spendable / is_unstakeable ──

    #[test]
    fn staked_output_never_spendable() {
        let output = make_wallet_output(
            [3; 32], 0, 102, 2_000_000_000,
            Some(StakingMeta { lock_tier: 1 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 5000);

        assert!(!td.is_spendable(5000 + tier_lock(1) + 1000));
        assert!(!td.is_spendable(5000));
    }

    #[test]
    fn regular_output_spendable() {
        let output = make_wallet_output([4; 32], 0, 103, 1_000_000_000, None);
        let td = TransferDetails::from_wallet_output(&output, 5000);
        assert!(td.is_spendable(6000));
    }

    #[test]
    fn staked_unstakeable_after_maturity() {
        let output = make_wallet_output(
            [5; 32], 0, 104, 3_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 5000);

        assert!(!td.is_unstakeable(5000 + tier_lock(0) - 1));
        assert!(td.is_unstakeable(5000 + tier_lock(0)));
        assert!(td.is_unstakeable(5000 + tier_lock(0) + 5000));
    }

    #[test]
    fn spent_staked_not_unstakeable() {
        let output = make_wallet_output(
            [6; 32], 0, 105, 1_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 5000);
        td.spent = true;
        assert!(!td.is_unstakeable(5000 + tier_lock(0) + 1000));
    }

    // ── has_claimable_rewards ──

    #[test]
    fn claimable_during_lock_period() {
        let output = make_wallet_output(
            [7; 32], 0, 106, 5_000_000_000,
            Some(StakingMeta { lock_tier: 2 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        // At height 5000, accrual_cap = min(5000, lock_until) = 5000, watermark = 1000
        assert!(td.has_claimable_rewards(5000));
    }

    #[test]
    fn claimable_after_maturity_with_backlog() {
        let output = make_wallet_output(
            [8; 32], 0, 107, 5_000_000_000,
            Some(StakingMeta { lock_tier: 1 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        let past_maturity = 1000 + tier_lock(1) + 1000;
        assert!(td.has_claimable_rewards(past_maturity));
    }

    #[test]
    fn not_claimable_after_full_drain() {
        let output = make_wallet_output(
            [9; 32], 0, 108, 5_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 1000);
        td.last_claimed_height = 1000 + tier_lock(0);

        assert!(!td.has_claimable_rewards(1000 + tier_lock(0) + 1000));
    }

    #[test]
    fn not_claimable_when_spent() {
        let output = make_wallet_output(
            [10; 32], 0, 109, 5_000_000_000,
            Some(StakingMeta { lock_tier: 1 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 1000);
        td.spent = true;
        assert!(!td.has_claimable_rewards(5000));
    }

    // ── ClaimableInfo ──

    #[test]
    fn claimable_info_from_transfer() {
        let output = make_wallet_output(
            [11; 32], 0, 110, 2_000_000_000,
            Some(StakingMeta { lock_tier: 2 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        let info = ClaimableInfo::from_transfer(&td, 0, 5000).unwrap();
        assert_eq!(info.from_height, 1000);
        assert_eq!(info.to_height, 5000);
        assert!(!info.accrual_frozen);
        assert_eq!(info.tier, 2);
        assert_eq!(info.range_blocks(), 4000);
    }

    #[test]
    fn claimable_info_with_watermark() {
        let output = make_wallet_output(
            [12; 32], 0, 111, 2_000_000_000,
            Some(StakingMeta { lock_tier: 1 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 1000);
        td.last_claimed_height = 3000;

        let info = ClaimableInfo::from_transfer(&td, 0, 5000).unwrap();
        assert_eq!(info.from_height, 3000);
        assert_eq!(info.to_height, 5000);
    }

    #[test]
    fn claimable_info_accrual_frozen() {
        let output = make_wallet_output(
            [13; 32], 0, 112, 2_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        let past_maturity = 1000 + tier_lock(0) + 1000;
        let info = ClaimableInfo::from_transfer(&td, 0, past_maturity).unwrap();
        assert_eq!(info.to_height, 1000 + tier_lock(0));
        assert!(info.accrual_frozen);
    }

    #[test]
    fn claimable_info_none_when_fully_claimed() {
        let output = make_wallet_output(
            [14; 32], 0, 113, 2_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 1000);
        td.last_claimed_height = 1000 + tier_lock(0);

        assert!(ClaimableInfo::from_transfer(&td, 0, 1000 + tier_lock(0) + 1000).is_none());
    }

    // ── WalletState integration ──

    #[test]
    fn wallet_state_auto_detects_staked_outputs() {
        let mut ws = WalletState::new();
        let outputs = vec![
            make_wallet_output([20; 32], 0, 200, 1_000_000_000, None),
            make_wallet_output(
                [20; 32], 1, 201, 5_000_000_000,
                Some(StakingMeta { lock_tier: 2 }),
            ),
        ];

        ws.process_scanned_outputs(1000, [0xAA; 32], make_timelocked(outputs));

        assert_eq!(ws.transfer_count(), 2);
        let transfers = ws.transfers();
        assert!(!transfers[0].staked);
        assert!(transfers[1].staked);
        assert_eq!(transfers[1].stake_tier, 2);
        assert_eq!(transfers[1].stake_lock_until, 1000 + tier_lock(2));
    }

    #[test]
    fn wallet_state_claimable_outputs() {
        let mut ws = WalletState::new();
        let outputs = vec![
            make_wallet_output(
                [21; 32], 0, 300, 2_000_000_000,
                Some(StakingMeta { lock_tier: 1 }),
            ),
            make_wallet_output(
                [21; 32], 1, 301, 3_000_000_000,
                Some(StakingMeta { lock_tier: 0 }),
            ),
        ];

        ws.process_scanned_outputs(1000, [0xBB; 32], make_timelocked(outputs));

        let claimable = ws.claimable_outputs(5000);
        assert_eq!(claimable.len(), 2);

        ws.update_claim_watermark(301, 1000 + tier_lock(0));
        let claimable = ws.claimable_outputs(1000 + tier_lock(0) + 1000);
        assert_eq!(claimable.len(), 1);
    }

    #[test]
    fn wallet_state_unstakeable_outputs() {
        let mut ws = WalletState::new();
        let outputs = vec![
            make_wallet_output(
                [22; 32], 0, 400, 2_000_000_000,
                Some(StakingMeta { lock_tier: 0 }),
            ),
            make_wallet_output(
                [22; 32], 1, 401, 3_000_000_000,
                Some(StakingMeta { lock_tier: 2 }),
            ),
        ];

        ws.process_scanned_outputs(1000, [0xCC; 32], make_timelocked(outputs));

        assert_eq!(ws.unstakeable_outputs(1000 + tier_lock(0) - 1).len(), 0);
        assert_eq!(ws.unstakeable_outputs(1000 + tier_lock(0)).len(), 1);
        assert_eq!(ws.unstakeable_outputs(1000 + tier_lock(2)).len(), 2);
    }

    // ── Reorg handling ──

    #[test]
    fn wallet_state_reorg_removes_staked_outputs() {
        let mut ws = WalletState::new();

        ws.process_scanned_outputs(
            1000,
            [0xD0; 32],
            make_timelocked(vec![
                make_wallet_output(
                    [30; 32], 0, 500, 5_000_000_000,
                    Some(StakingMeta { lock_tier: 1 }),
                ),
            ]),
        );

        ws.process_scanned_outputs(
            2000,
            [0xD1; 32],
            make_timelocked(vec![
                make_wallet_output(
                    [31; 32], 0, 501, 1_000_000_000,
                    Some(StakingMeta { lock_tier: 0 }),
                ),
            ]),
        );

        assert_eq!(ws.transfer_count(), 2);

        // Reorg at height 2000 removes the second output
        ws.handle_reorg(2000);
        assert_eq!(ws.transfer_count(), 1);
        assert!(ws.transfers()[0].staked);
        assert_eq!(ws.transfers()[0].stake_tier, 1);
    }

    // ── Spend detection with claim inputs ──

    #[test]
    fn detect_spends_marks_staked_output_spent() {
        let mut ws = WalletState::new();
        let outputs = vec![make_wallet_output(
            [40; 32], 0, 600, 2_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        )];

        ws.process_scanned_outputs(1000, [0xE0; 32], make_timelocked(outputs));
        ws.set_key_image(0, [0xFF; 32]);

        let past_maturity = 1000 + tier_lock(0) + 1000;
        assert!(ws.transfers()[0].staked);
        assert!(!ws.transfers()[0].spent);
        assert!(ws.transfers()[0].is_unstakeable(past_maturity));

        ws.detect_spends(past_maturity, &[[0xFF; 32]]);
        assert!(ws.transfers()[0].spent);
        assert!(!ws.transfers()[0].is_unstakeable(past_maturity));
        assert!(!ws.transfers()[0].has_claimable_rewards(past_maturity));
    }

    // ── Watermark update ──

    #[test]
    fn watermark_update_advances_claim_range() {
        let mut ws = WalletState::new();
        let outputs = vec![make_wallet_output(
            [50; 32], 0, 700, 5_000_000_000,
            Some(StakingMeta { lock_tier: 2 }),
        )];

        ws.process_scanned_outputs(1000, [0xF0; 32], make_timelocked(outputs));

        let td = &ws.transfers()[0];
        assert_eq!(td.last_claimed_height, 0);

        let info = ClaimableInfo::from_transfer(td, 0, 5000).unwrap();
        assert_eq!(info.from_height, 1000);

        ws.update_claim_watermark(700, 5000);

        let td = &ws.transfers()[0];
        assert_eq!(td.last_claimed_height, 5000);

        let info = ClaimableInfo::from_transfer(td, 0, 10000).unwrap();
        assert_eq!(info.from_height, 5000);
        assert_eq!(info.to_height, 10000);
    }
}
