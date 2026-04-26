// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#[cfg(test)]
mod lifecycle {
    use shekyl_oxide::transaction::StakingMeta;
    use shekyl_scanner::{
        staker_pool::AccrualRecord, LedgerBlock, LedgerIndexes, LedgerIndexesExt,
    };

    use crate::{
        claim_builder::ClaimTxBuilder, error::WalletCoreError, workflow::plan_claim_and_unstake,
    };

    fn make_wallet_output(
        tx_hash: [u8; 32],
        _index: u64,
        global_index: u64,
        amount: u64,
        staking: Option<StakingMeta>,
    ) -> shekyl_scanner::RecoveredWalletOutput {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
        use shekyl_oxide::primitives::Commitment;

        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&global_index.to_le_bytes());
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let key = &scalar * ED25519_BASEPOINT_TABLE;

        let base = shekyl_scanner::WalletOutput::new_for_test(
            tx_hash,
            0,
            global_index,
            key,
            Scalar::ZERO,
            Commitment {
                mask: Scalar::ONE,
                amount,
            },
            staking,
        );
        shekyl_scanner::RecoveredWalletOutput::new_for_test(base, amount)
    }

    fn simple_weight_fn(amount: u64, tier: u8) -> u64 {
        let multiplier = match tier {
            1 => 150,
            2 => 200,
            _ => 100,
        };
        amount * multiplier / 100
    }

    fn setup_wallet_with_staked_output(
        amount: u64,
        tier: u8,
        creation_height: u64,
    ) -> (LedgerBlock, LedgerIndexes) {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        let output = make_wallet_output(
            [1; 32],
            0,
            100,
            amount,
            Some(StakingMeta { lock_tier: tier }),
        );
        indexes.process_scanned_outputs(
            &mut ledger,
            creation_height,
            [0xAA; 32],
            shekyl_scanner::scan::Timelocked::from_vec(vec![output]),
        );
        (ledger, indexes)
    }

    fn populate_accrual(
        indexes: &mut LedgerIndexes,
        from: u64,
        to: u64,
        emission: u64,
        total_weighted: u128,
    ) {
        for h in from..=to {
            indexes.insert_accrual(
                h,
                AccrualRecord {
                    staker_emission: emission,
                    staker_fee_pool: 0,
                    total_weighted_stake: total_weighted,
                },
            );
        }
    }

    // ── Claim builder tests ──

    #[test]
    fn plan_all_claims_basic() {
        let (ledger, mut indexes) = setup_wallet_with_staked_output(5_000_000_000, 1, 1000);
        populate_accrual(&mut indexes, 1001, 5000, 100_000, 10_000_000_000);

        let builder = ClaimTxBuilder::new(10000);
        let plan = builder
            .plan_all(&ledger, &indexes, 5000, simple_weight_fn)
            .unwrap();

        assert_eq!(plan.claims.len(), 1);
        assert_eq!(plan.claims[0].from_height, 1000);
        assert_eq!(plan.claims[0].to_height, 5000);
        assert!(plan.total_reward > 0);
    }

    #[test]
    fn plan_claim_splits_large_ranges() {
        let (ledger, mut indexes) = setup_wallet_with_staked_output(5_000_000_000, 2, 1000);
        populate_accrual(&mut indexes, 1001, 12000, 100_000, 10_000_000_000);

        let builder = ClaimTxBuilder::new(5000);
        let plan = builder
            .plan_all(&ledger, &indexes, 12000, simple_weight_fn)
            .unwrap();

        assert!(plan.claims.len() >= 3);
    }

    #[test]
    fn plan_claim_respects_watermark() {
        let lock_blocks = shekyl_staking::tiers::tier_by_id(0).unwrap().lock_blocks;
        let creation = 1000u64;
        let lock_until = creation + lock_blocks;
        let watermark = creation + lock_blocks / 2;

        let (mut ledger, mut indexes) = setup_wallet_with_staked_output(5_000_000_000, 0, creation);
        populate_accrual(
            &mut indexes,
            creation + 1,
            lock_until,
            100_000,
            10_000_000_000,
        );

        ledger.update_claim_watermark(100, watermark);

        let builder = ClaimTxBuilder::new(lock_blocks);
        let plan = builder
            .plan_all(&ledger, &indexes, lock_until, simple_weight_fn)
            .unwrap();

        assert_eq!(plan.claims[0].from_height, watermark);
    }

    #[test]
    fn plan_claim_errors_on_no_claimable() {
        let (mut ledger, indexes) = setup_wallet_with_staked_output(5_000_000_000, 0, 1000);
        ledger.update_claim_watermark(100, 10000);

        let builder = ClaimTxBuilder::new(10000);
        let result = builder.plan_all(&ledger, &indexes, 15000, simple_weight_fn);
        assert!(result.is_err());
    }

    #[test]
    fn plan_specific_rejects_non_staked() {
        let mut ledger = LedgerBlock::empty();
        let mut indexes = LedgerIndexes::empty();
        let output = make_wallet_output([2; 32], 0, 200, 1_000_000_000, None);
        indexes.process_scanned_outputs(
            &mut ledger,
            1000,
            [0xBB; 32],
            shekyl_scanner::scan::Timelocked::from_vec(vec![output]),
        );

        let builder = ClaimTxBuilder::new(10000);
        let result = builder.plan_specific(&ledger, &indexes, &[0], 5000, simple_weight_fn);
        assert!(matches!(result, Err(WalletCoreError::NotStaked { .. })));
    }

    // ── Claim-and-unstake workflow ──

    #[test]
    fn claim_and_unstake_with_backlog() {
        let (ledger, mut indexes) = setup_wallet_with_staked_output(5_000_000_000, 0, 1000);
        populate_accrual(&mut indexes, 1001, 10000, 100_000, 10_000_000_000);

        let plan = plan_claim_and_unstake(&ledger, &indexes, &[0], 15000, 10000, simple_weight_fn)
            .unwrap();

        assert!(plan.claim_plan.is_some());
        assert_eq!(plan.unstake_indices, vec![0]);
        assert_eq!(plan.total_unstake_amount, 5_000_000_000);
    }

    #[test]
    fn claim_and_unstake_no_backlog() {
        let (mut ledger, indexes) = setup_wallet_with_staked_output(5_000_000_000, 0, 1000);
        ledger.update_claim_watermark(100, 10000);

        let plan = plan_claim_and_unstake(&ledger, &indexes, &[0], 15000, 10000, simple_weight_fn)
            .unwrap();

        assert!(plan.claim_plan.is_none());
        assert_eq!(plan.unstake_indices, vec![0]);
    }

    #[test]
    fn claim_and_unstake_rejects_locked() {
        let (ledger, indexes) = setup_wallet_with_staked_output(5_000_000_000, 2, 1000);

        let result = plan_claim_and_unstake(&ledger, &indexes, &[0], 5000, 10000, simple_weight_fn);
        assert!(matches!(result, Err(WalletCoreError::NotMatured { .. })));
    }

    #[test]
    fn claim_and_unstake_rejects_spent() {
        let (mut ledger, mut indexes) = setup_wallet_with_staked_output(5_000_000_000, 0, 1000);
        indexes.set_key_image(&mut ledger, 0, [0xFF; 32]);
        indexes.detect_spends(&mut ledger, 15000, &[[0xFF; 32]]);

        let result =
            plan_claim_and_unstake(&ledger, &indexes, &[0], 15000, 10000, simple_weight_fn);
        assert!(matches!(result, Err(WalletCoreError::AlreadySpent { .. })));
    }

    // ── Reward computation parity ──

    #[test]
    fn reward_matches_manual_calculation() {
        let amount = 10_000_000_000u64;
        let tier = 1u8;
        let weight = simple_weight_fn(amount, tier);

        let emission = 1_000_000u64;
        let total_weighted: u128 = 100_000_000_000;

        #[allow(clippy::cast_possible_truncation)]
        let expected_per_block =
            (u128::from(emission) * u128::from(weight) / total_weighted) as u64;
        assert_eq!(expected_per_block, 150_000);

        let (ledger, mut indexes) = setup_wallet_with_staked_output(amount, tier, 1000);
        populate_accrual(&mut indexes, 1001, 1010, emission, total_weighted);

        let builder = ClaimTxBuilder::new(10000);
        let plan = builder
            .plan_all(&ledger, &indexes, 1010, simple_weight_fn)
            .unwrap();

        assert_eq!(plan.total_reward, 1_500_000);
    }
}
