// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for scanner staking detection, claim tracking, and wallet state.

#[cfg(test)]
pub(crate) mod staking {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_oxide::{primitives::Commitment, transaction::StakingMeta};
    use zeroize::Zeroizing;

    use crate::{
        claim::ClaimableInfo,
        output::*,
        runtime_ext::{TransferDetailsExt, WalletStateExt},
        scan::{RecoveredWalletOutput, Timelocked},
        transfer::TransferDetails,
        wallet_state::WalletState,
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
            absolute_id: AbsoluteId {
                transaction: tx_hash,
                index_in_transaction: index,
            },
            relative_id: RelativeId {
                index_on_blockchain: global_index,
            },
            data: OutputData {
                key: unique_point(global_index),
                key_offset: Scalar::ZERO,
                commitment: Commitment {
                    mask: Scalar::ONE,
                    amount,
                },
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

    /// Wrap a plain WalletOutput in a RecoveredWalletOutput with dummy KEM secrets.
    /// For testing wallet state management only — the secrets are all zeroes.
    fn wrap_recovered(output: WalletOutput, amount: u64) -> RecoveredWalletOutput {
        let mut ki = [0u8; 32];
        ki[..8].copy_from_slice(&output.index_on_blockchain().to_le_bytes());
        RecoveredWalletOutput {
            base: output,
            ho: Zeroizing::new([0u8; 32]),
            y: Zeroizing::new([0u8; 32]),
            z: Zeroizing::new([0u8; 32]),
            k_amount: Zeroizing::new([0u8; 32]),
            combined_shared_secret: Zeroizing::new([0u8; 64]),
            key_image: ki,
            amount,
        }
    }

    fn make_timelocked(outputs: Vec<(WalletOutput, u64)>) -> Timelocked {
        Timelocked(
            outputs
                .into_iter()
                .map(|(o, a)| wrap_recovered(o, a))
                .collect(),
        )
    }

    // ── Staking detection ──

    #[test]
    fn from_wallet_output_detects_staked() {
        let output = make_wallet_output(
            [1; 32],
            0,
            100,
            5_000_000_000,
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
            [3; 32],
            0,
            102,
            2_000_000_000,
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
            [5; 32],
            0,
            104,
            3_000_000_000,
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
            [6; 32],
            0,
            105,
            1_000_000_000,
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
            [7; 32],
            0,
            106,
            5_000_000_000,
            Some(StakingMeta { lock_tier: 2 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        // At height 5000, accrual_cap = min(5000, lock_until) = 5000, watermark = 1000
        assert!(td.has_claimable_rewards(5000));
    }

    #[test]
    fn claimable_after_maturity_with_backlog() {
        let output = make_wallet_output(
            [8; 32],
            0,
            107,
            5_000_000_000,
            Some(StakingMeta { lock_tier: 1 }),
        );
        let td = TransferDetails::from_wallet_output(&output, 1000);

        let past_maturity = 1000 + tier_lock(1) + 1000;
        assert!(td.has_claimable_rewards(past_maturity));
    }

    #[test]
    fn not_claimable_after_full_drain() {
        let output = make_wallet_output(
            [9; 32],
            0,
            108,
            5_000_000_000,
            Some(StakingMeta { lock_tier: 0 }),
        );
        let mut td = TransferDetails::from_wallet_output(&output, 1000);
        td.last_claimed_height = 1000 + tier_lock(0);

        assert!(!td.has_claimable_rewards(1000 + tier_lock(0) + 1000));
    }

    #[test]
    fn not_claimable_when_spent() {
        let output = make_wallet_output(
            [10; 32],
            0,
            109,
            5_000_000_000,
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
            [11; 32],
            0,
            110,
            2_000_000_000,
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
            [12; 32],
            0,
            111,
            2_000_000_000,
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
            [13; 32],
            0,
            112,
            2_000_000_000,
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
            [14; 32],
            0,
            113,
            2_000_000_000,
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
            (
                make_wallet_output([20; 32], 0, 200, 1_000_000_000, None),
                1_000_000_000,
            ),
            (
                make_wallet_output(
                    [20; 32],
                    1,
                    201,
                    5_000_000_000,
                    Some(StakingMeta { lock_tier: 2 }),
                ),
                5_000_000_000,
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
            (
                make_wallet_output(
                    [21; 32],
                    0,
                    300,
                    2_000_000_000,
                    Some(StakingMeta { lock_tier: 1 }),
                ),
                2_000_000_000,
            ),
            (
                make_wallet_output(
                    [21; 32],
                    1,
                    301,
                    3_000_000_000,
                    Some(StakingMeta { lock_tier: 0 }),
                ),
                3_000_000_000,
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
            (
                make_wallet_output(
                    [22; 32],
                    0,
                    400,
                    2_000_000_000,
                    Some(StakingMeta { lock_tier: 0 }),
                ),
                2_000_000_000,
            ),
            (
                make_wallet_output(
                    [22; 32],
                    1,
                    401,
                    3_000_000_000,
                    Some(StakingMeta { lock_tier: 2 }),
                ),
                3_000_000_000,
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
            make_timelocked(vec![(
                make_wallet_output(
                    [30; 32],
                    0,
                    500,
                    5_000_000_000,
                    Some(StakingMeta { lock_tier: 1 }),
                ),
                5_000_000_000,
            )]),
        );

        ws.process_scanned_outputs(
            2000,
            [0xD1; 32],
            make_timelocked(vec![(
                make_wallet_output(
                    [31; 32],
                    0,
                    501,
                    1_000_000_000,
                    Some(StakingMeta { lock_tier: 0 }),
                ),
                1_000_000_000,
            )]),
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
        let outputs = vec![(
            make_wallet_output(
                [40; 32],
                0,
                600,
                2_000_000_000,
                Some(StakingMeta { lock_tier: 0 }),
            ),
            2_000_000_000,
        )];

        ws.process_scanned_outputs(1000, [0xE0; 32], make_timelocked(outputs));

        let past_maturity = 1000 + tier_lock(0) + 1000;
        assert!(ws.transfers()[0].staked);
        assert!(!ws.transfers()[0].spent);
        assert!(ws.transfers()[0].is_unstakeable(past_maturity));

        let ki = ws.transfers()[0]
            .key_image
            .expect("key image should be set by process_scanned_outputs");
        ws.detect_spends(past_maturity, &[ki]);
        assert!(ws.transfers()[0].spent);
        assert!(!ws.transfers()[0].is_unstakeable(past_maturity));
        assert!(!ws.transfers()[0].has_claimable_rewards(past_maturity));
    }

    // ── Watermark update ──

    #[test]
    fn watermark_update_advances_claim_range() {
        let mut ws = WalletState::new();
        let outputs = vec![(
            make_wallet_output(
                [50; 32],
                0,
                700,
                5_000_000_000,
                Some(StakingMeta { lock_tier: 2 }),
            ),
            5_000_000_000,
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

    // ── Gate 5a: unmark_spent unit tests ──

    #[test]
    fn unmark_spent_returns_output_to_spendable_pool() {
        let mut ws = WalletState::new();
        let outputs = vec![
            (
                make_wallet_output([60; 32], 0, 800, 1_000_000_000, None),
                1_000_000_000,
            ),
            (
                make_wallet_output([60; 32], 1, 801, 2_000_000_000, None),
                2_000_000_000,
            ),
        ];
        ws.process_scanned_outputs(100, [0xA0; 32], make_timelocked(outputs));

        let ki_0 = ws.transfers()[0].key_image.unwrap();
        let ki_1 = ws.transfers()[1].key_image.unwrap();

        assert!(ws.mark_spent(&ki_0, 200));
        assert!(ws.mark_spent(&ki_1, 200));
        assert!(ws.transfers()[0].spent);
        assert!(ws.transfers()[1].spent);

        let balance_before = ws.balance(1000);
        assert_eq!(balance_before.total, 0, "both spent → zero total");

        let unmarked = ws.unmark_spent(&[ki_0, ki_1]);
        assert_eq!(unmarked, 2);
        assert!(!ws.transfers()[0].spent);
        assert!(!ws.transfers()[1].spent);
        assert!(ws.transfers()[0].spent_height.is_none());
        assert!(ws.transfers()[1].spent_height.is_none());

        let balance_after = ws.balance(1000);
        assert_eq!(balance_after.total, 3_000_000_000);
        assert_eq!(balance_after.unlocked, 3_000_000_000);
    }

    #[test]
    fn unmark_spent_unknown_key_image_is_noop() {
        let mut ws = WalletState::new();
        let outputs = vec![(
            make_wallet_output([61; 32], 0, 810, 1_000_000_000, None),
            1_000_000_000,
        )];
        ws.process_scanned_outputs(100, [0xA1; 32], make_timelocked(outputs));

        let bogus_ki = [0xFFu8; 32];
        let unmarked = ws.unmark_spent(&[bogus_ki]);
        assert_eq!(unmarked, 0);
        assert!(!ws.transfers()[0].spent);
    }

    #[test]
    fn unmark_spent_idempotent_on_already_unspent() {
        let mut ws = WalletState::new();
        let outputs = vec![(
            make_wallet_output([62; 32], 0, 820, 1_000_000_000, None),
            1_000_000_000,
        )];
        ws.process_scanned_outputs(100, [0xA2; 32], make_timelocked(outputs));

        let ki = ws.transfers()[0].key_image.unwrap();
        let unmarked = ws.unmark_spent(&[ki]);
        assert_eq!(unmarked, 0, "already unspent → no change");
    }

    #[test]
    fn unmark_spent_partial_set() {
        let mut ws = WalletState::new();
        let outputs = vec![
            (
                make_wallet_output([63; 32], 0, 830, 1_000_000_000, None),
                1_000_000_000,
            ),
            (
                make_wallet_output([63; 32], 1, 831, 2_000_000_000, None),
                2_000_000_000,
            ),
            (
                make_wallet_output([63; 32], 2, 832, 3_000_000_000, None),
                3_000_000_000,
            ),
        ];
        ws.process_scanned_outputs(100, [0xA3; 32], make_timelocked(outputs));

        let ki_0 = ws.transfers()[0].key_image.unwrap();
        let ki_1 = ws.transfers()[1].key_image.unwrap();
        let ki_2 = ws.transfers()[2].key_image.unwrap();

        ws.mark_spent(&ki_0, 200);
        ws.mark_spent(&ki_1, 200);
        ws.mark_spent(&ki_2, 200);

        let unmarked = ws.unmark_spent(&[ki_1]);
        assert_eq!(unmarked, 1);
        assert!(ws.transfers()[0].spent);
        assert!(!ws.transfers()[1].spent);
        assert!(ws.transfers()[2].spent);

        let balance = ws.balance(1000);
        assert_eq!(balance.total, 2_000_000_000);
        assert_eq!(balance.unlocked, 2_000_000_000);
    }

    #[test]
    fn unmark_spent_preserves_invariants() {
        let mut ws = WalletState::new();
        let outputs = vec![
            (
                make_wallet_output([64; 32], 0, 840, 500_000_000, None),
                500_000_000,
            ),
            (
                make_wallet_output(
                    [64; 32],
                    1,
                    841,
                    1_000_000_000,
                    Some(StakingMeta { lock_tier: 1 }),
                ),
                1_000_000_000,
            ),
        ];
        ws.process_scanned_outputs(100, [0xA4; 32], make_timelocked(outputs));

        let ki_0 = ws.transfers()[0].key_image.unwrap();
        let ki_1 = ws.transfers()[1].key_image.unwrap();

        ws.mark_spent(&ki_0, 200);
        ws.mark_spent(&ki_1, 200);
        ws.check_invariants().expect("invariants after mark_spent");

        ws.unmark_spent(&[ki_0, ki_1]);
        ws.check_invariants()
            .expect("invariants after unmark_spent");

        assert_eq!(ws.balance(1000).total, 1_500_000_000);
    }

    // ── Gate 5a: immature output rejection (regression) ──

    #[test]
    fn immature_output_not_spendable() {
        let mut ws = WalletState::new();
        let outputs = vec![(
            make_wallet_output([65; 32], 0, 850, 1_000_000_000, None),
            1_000_000_000,
        )];
        ws.process_scanned_outputs(100, [0xA5; 32], make_timelocked(outputs));

        let spendable = ws.spendable_outputs(105, None, None);
        assert!(
            spendable.is_empty(),
            "output mined at 100 should NOT be spendable at 105"
        );

        let spendable = ws.spendable_outputs(110, None, None);
        assert_eq!(
            spendable.len(),
            1,
            "output mined at 100 should be spendable at 110"
        );
    }

    // ── Gate 5b: explicit check_invariants tests ──

    #[test]
    fn invariants_hold_on_fresh_state() {
        let ws = WalletState::new();
        ws.check_invariants().expect("fresh state invariants");
    }

    #[test]
    fn invariants_hold_after_process_and_spend_cycle() {
        let mut ws = WalletState::new();
        let outputs = vec![
            (make_wallet_output([66; 32], 0, 860, 1_000, None), 1_000),
            (make_wallet_output([66; 32], 1, 861, 2_000, None), 2_000),
        ];
        ws.process_scanned_outputs(100, [0xB0; 32], make_timelocked(outputs));
        ws.check_invariants().expect("after process");

        let ki = ws.transfers()[0].key_image.unwrap();
        ws.mark_spent(&ki, 200);
        ws.check_invariants().expect("after mark_spent");

        ws.unmark_spent(&[ki]);
        ws.check_invariants().expect("after unmark_spent");

        ws.freeze(0);
        ws.check_invariants().expect("after freeze");

        ws.thaw(0);
        ws.check_invariants().expect("after thaw");

        ws.handle_reorg(200);
        ws.check_invariants()
            .expect("after reorg (noop — no blocks at 200)");

        ws.handle_reorg(50);
        ws.check_invariants().expect("after reorg removing all");
        assert_eq!(ws.transfer_count(), 0);
    }

    #[test]
    fn invariants_hold_after_reorg_with_multiple_blocks() {
        let mut ws = WalletState::new();

        ws.process_scanned_outputs(
            100,
            [0xC0; 32],
            make_timelocked(vec![(
                make_wallet_output([70; 32], 0, 900, 1_000, None),
                1_000,
            )]),
        );
        ws.process_scanned_outputs(
            200,
            [0xC1; 32],
            make_timelocked(vec![(
                make_wallet_output([71; 32], 0, 901, 2_000, None),
                2_000,
            )]),
        );
        ws.process_scanned_outputs(
            300,
            [0xC2; 32],
            make_timelocked(vec![(
                make_wallet_output([72; 32], 0, 902, 3_000, None),
                3_000,
            )]),
        );
        ws.check_invariants().expect("3 blocks");

        ws.handle_reorg(200);
        ws.check_invariants().expect("after reorg at 200");
        assert_eq!(ws.transfer_count(), 1);
        assert_eq!(ws.height(), 100);
    }
}

/// Gate 5c: Property tests for WalletState invariants under random operation sequences.
///
/// Uses proptest to generate random interleaving of process_scanned_outputs,
/// mark_spent, unmark_spent, freeze, thaw, and handle_reorg, then asserts
/// `check_invariants()` holds after every operation.
#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
mod wallet_state_proptest {
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::*;

    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_oxide::primitives::Commitment;
    use zeroize::Zeroizing;

    use crate::{
        output::*,
        runtime_ext::WalletStateExt,
        scan::{RecoveredWalletOutput, Timelocked},
        wallet_state::WalletState,
    };

    fn unique_point(seed: u64) -> curve25519_dalek::EdwardsPoint {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let scalar = Scalar::from_bytes_mod_order(bytes);
        &scalar * ED25519_BASEPOINT_TABLE
    }

    fn make_output(global_index: u64, amount: u64) -> WalletOutput {
        WalletOutput {
            absolute_id: AbsoluteId {
                transaction: {
                    let mut h = [0u8; 32];
                    h[..8].copy_from_slice(&global_index.to_le_bytes());
                    h
                },
                index_in_transaction: 0,
            },
            relative_id: RelativeId {
                index_on_blockchain: global_index,
            },
            data: OutputData {
                key: unique_point(global_index),
                key_offset: Scalar::ZERO,
                commitment: Commitment {
                    mask: Scalar::ONE,
                    amount,
                },
            },
            metadata: Metadata {
                additional_timelock: shekyl_oxide::transaction::Timelock::None,
                subaddress: None,
                payment_id: None,
                arbitrary_data: vec![],
            },
            staking: None,
        }
    }

    fn wrap_recovered(output: WalletOutput, amount: u64) -> RecoveredWalletOutput {
        let mut ki = [0u8; 32];
        ki[..8].copy_from_slice(&output.index_on_blockchain().to_le_bytes());
        RecoveredWalletOutput {
            base: output,
            ho: Zeroizing::new([0u8; 32]),
            y: Zeroizing::new([0u8; 32]),
            z: Zeroizing::new([0u8; 32]),
            k_amount: Zeroizing::new([0u8; 32]),
            combined_shared_secret: Zeroizing::new([0u8; 64]),
            key_image: ki,
            amount,
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        AddOutputs { count: usize, base_amount: u64 },
        MarkSpent { frac: f64 },
        UnmarkSpent { frac: f64 },
        Freeze { frac: f64 },
        Thaw { frac: f64 },
        Reorg { frac: f64 },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            10 => (1..4usize, 1..100_000u64).prop_map(|(c, a)| Op::AddOutputs { count: c, base_amount: a }),
            3 => (0.0..1.0f64).prop_map(|f| Op::MarkSpent { frac: f }),
            2 => (0.0..1.0f64).prop_map(|f| Op::UnmarkSpent { frac: f }),
            1 => (0.0..1.0f64).prop_map(|f| Op::Freeze { frac: f }),
            1 => (0.0..1.0f64).prop_map(|f| Op::Thaw { frac: f }),
            1 => (0.0..1.0f64).prop_map(|f| Op::Reorg { frac: f }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]
        #[test]
        fn invariants_hold_under_random_operations(ops in prop_vec(op_strategy(), 1..40)) {
            let mut ws = WalletState::new();
            let mut next_global_index: u64 = 0;
            let mut next_height: u64 = 100;

            for op in &ops {
                match op {
                    Op::AddOutputs { count, base_amount } => {
                        let outputs: Vec<RecoveredWalletOutput> = (0..*count).map(|i| {
                            let gi = next_global_index;
                            next_global_index += 1;
                            let o = make_output(gi, base_amount + i as u64);
                            wrap_recovered(o, base_amount + i as u64)
                        }).collect();
                        ws.process_scanned_outputs(
                            next_height,
                            {
                                let mut h = [0u8; 32];
                                h[..8].copy_from_slice(&next_height.to_le_bytes());
                                h
                            },
                            Timelocked(outputs),
                        );
                        next_height += 10;
                    }
                    Op::MarkSpent { frac } => {
                        let count = ws.transfer_count();
                        if count > 0 {
                            let idx = ((*frac * count as f64) as usize).min(count - 1);
                            if let Some(ki) = ws.transfers()[idx].key_image {
                                ws.mark_spent(&ki, next_height);
                            }
                        }
                    }
                    Op::UnmarkSpent { frac } => {
                        let count = ws.transfer_count();
                        if count > 0 {
                            let idx = ((*frac * count as f64) as usize).min(count - 1);
                            if let Some(ki) = ws.transfers()[idx].key_image {
                                ws.unmark_spent(&[ki]);
                            }
                        }
                    }
                    Op::Freeze { frac } => {
                        let count = ws.transfer_count();
                        if count > 0 {
                            let idx = ((*frac * count as f64) as usize).min(count - 1);
                            ws.freeze(idx);
                        }
                    }
                    Op::Thaw { frac } => {
                        let count = ws.transfer_count();
                        if count > 0 {
                            let idx = ((*frac * count as f64) as usize).min(count - 1);
                            ws.thaw(idx);
                        }
                    }
                    Op::Reorg { frac } => {
                        if ws.height() > 0 {
                            let fork_at = ((ws.height() as f64 * frac) as u64).max(1);
                            ws.handle_reorg(fork_at);
                            next_height = ws.height() + 10;
                        }
                    }
                }

                ws.check_invariants().unwrap_or_else(|e| {
                    panic!(
                        "invariant violated after {:?} (transfers={}, height={}): {}",
                        op, ws.transfer_count(), ws.height(), e
                    );
                });
            }
        }
    }
}

/// Gate 7: Sync-loop bookkeeping tests using a mock block source.
///
/// **Bookkeeping test only.** This module exercises the sync loop's
/// state-management behavior (progress monotonicity, reorg handling,
/// spend detection tracking) using manually constructed blocks fed
/// directly into WalletState. It does NOT test the RPC layer, the
/// daemon's block format, or the scanner's KEM/HKDF pipeline. A
/// green Gate 7 means the sync loop's bookkeeping is correct against
/// a cooperative mock — it does NOT mean the scanner works against a
/// real daemon. Real-daemon coverage belongs in the stressnet gate.
#[cfg(test)]
mod sync_bookkeeping {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_oxide::primitives::Commitment;
    use zeroize::Zeroizing;

    use crate::{
        output::*,
        runtime_ext::WalletStateExt,
        scan::{RecoveredWalletOutput, Timelocked},
        wallet_state::WalletState,
    };

    fn unique_point(seed: u64) -> curve25519_dalek::EdwardsPoint {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let scalar = Scalar::from_bytes_mod_order(bytes);
        &scalar * ED25519_BASEPOINT_TABLE
    }

    fn mock_output(global_index: u64, amount: u64) -> RecoveredWalletOutput {
        let mut ki = [0u8; 32];
        ki[..8].copy_from_slice(&global_index.to_le_bytes());
        RecoveredWalletOutput {
            base: WalletOutput {
                absolute_id: AbsoluteId {
                    transaction: {
                        let mut h = [0u8; 32];
                        h[..8].copy_from_slice(&global_index.to_le_bytes());
                        h
                    },
                    index_in_transaction: 0,
                },
                relative_id: RelativeId {
                    index_on_blockchain: global_index,
                },
                data: OutputData {
                    key: unique_point(global_index),
                    key_offset: Scalar::ZERO,
                    commitment: Commitment {
                        mask: Scalar::ONE,
                        amount,
                    },
                },
                metadata: Metadata {
                    additional_timelock: shekyl_oxide::transaction::Timelock::None,
                    subaddress: None,
                    payment_id: None,
                    arbitrary_data: vec![],
                },
                staking: None,
            },
            ho: Zeroizing::new([0u8; 32]),
            y: Zeroizing::new([0u8; 32]),
            z: Zeroizing::new([0u8; 32]),
            k_amount: Zeroizing::new([0u8; 32]),
            combined_shared_secret: Zeroizing::new([0u8; 64]),
            key_image: ki,
            amount,
        }
    }

    fn block_hash(height: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&height.to_le_bytes());
        h[8] = 0xBB;
        h
    }

    /// Simulate a mock block source: each block has N outputs with given amounts.
    struct MockBlockSource {
        blocks: Vec<(u64, Vec<(u64, u64)>)>,
        next_global: u64,
    }

    impl MockBlockSource {
        fn new() -> Self {
            Self {
                blocks: Vec::new(),
                next_global: 0,
            }
        }

        fn add_block(&mut self, height: u64, amounts: &[u64]) {
            let outputs: Vec<(u64, u64)> = amounts
                .iter()
                .map(|&a| {
                    let gi = self.next_global;
                    self.next_global += 1;
                    (gi, a)
                })
                .collect();
            self.blocks.push((height, outputs));
        }
    }

    #[test]
    fn progress_is_monotonically_increasing() {
        let mut source = MockBlockSource::new();
        source.add_block(1, &[1000]);
        source.add_block(2, &[2000, 3000]);
        source.add_block(3, &[]);
        source.add_block(4, &[5000]);

        let mut ws = WalletState::new();
        let mut heights: Vec<u64> = Vec::new();

        for (height, outputs) in &source.blocks {
            let recovered: Vec<RecoveredWalletOutput> = outputs
                .iter()
                .map(|&(gi, amount)| mock_output(gi, amount))
                .collect();

            ws.process_scanned_outputs(*height, block_hash(*height), Timelocked(recovered));
            heights.push(ws.height());
        }

        for window in heights.windows(2) {
            assert!(
                window[1] >= window[0],
                "progress went backwards: {} → {}",
                window[0],
                window[1]
            );
        }
        assert_eq!(*heights.last().unwrap(), 4);
        ws.check_invariants().expect("final invariants");
    }

    #[test]
    fn spend_detection_through_mock_blocks() {
        let mut ws = WalletState::new();

        let o1 = mock_output(100, 5000);
        let ki_100 = o1.key_image;
        let o2 = mock_output(101, 3000);
        ws.process_scanned_outputs(10, block_hash(10), Timelocked(vec![o1, o2]));

        assert_eq!(ws.transfer_count(), 2);
        assert_eq!(ws.balance(100).total, 8000);

        ws.detect_spends(20, &[ki_100]);
        assert!(ws.transfers()[0].spent);
        assert!(!ws.transfers()[1].spent);
        assert_eq!(ws.balance(100).total, 3000);
        ws.check_invariants().expect("after spend detection");
    }

    #[test]
    fn reorg_restores_state_correctly() {
        let mut ws = WalletState::new();

        ws.process_scanned_outputs(10, block_hash(10), Timelocked(vec![mock_output(200, 1000)]));
        ws.process_scanned_outputs(20, block_hash(20), Timelocked(vec![mock_output(201, 2000)]));
        ws.process_scanned_outputs(30, block_hash(30), Timelocked(vec![mock_output(202, 3000)]));

        assert_eq!(ws.transfer_count(), 3);
        assert_eq!(ws.balance(100).total, 6000);

        ws.handle_reorg(20);

        assert_eq!(ws.transfer_count(), 1);
        assert_eq!(ws.height(), 10);
        assert_eq!(ws.balance(100).total, 1000);
        ws.check_invariants().expect("after reorg");

        ws.process_scanned_outputs(20, block_hash(20), Timelocked(vec![mock_output(301, 7000)]));

        assert_eq!(ws.transfer_count(), 2);
        assert_eq!(ws.balance(100).total, 8000);
        ws.check_invariants().expect("after re-scan post-reorg");
    }

    #[test]
    fn empty_blocks_advance_height() {
        let mut ws = WalletState::new();

        for h in 1..=10 {
            ws.process_scanned_outputs(h, block_hash(h), Timelocked(vec![]));
        }

        assert_eq!(ws.height(), 10);
        assert_eq!(ws.transfer_count(), 0);
        ws.check_invariants().expect("empty blocks invariants");
    }

    #[test]
    fn detect_spends_then_unmark_round_trip() {
        let mut ws = WalletState::new();

        let o = mock_output(500, 10_000);
        let ki = o.key_image;
        ws.process_scanned_outputs(10, block_hash(10), Timelocked(vec![o]));

        let spent = ws.detect_spends(20, &[ki]);
        assert_eq!(spent, 1);
        assert_eq!(ws.balance(100).total, 0);

        let unmarked = ws.unmark_spent(&[ki]);
        assert_eq!(unmarked, 1);
        assert_eq!(ws.balance(100).total, 10_000);

        ws.check_invariants().expect("round-trip invariants");
    }
}
