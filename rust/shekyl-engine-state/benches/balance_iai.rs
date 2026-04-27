// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/balance.rs`.
//!
//! Same workload (build N synthetic `TransferDetails`, compute
//! `BalanceSummary`) measured via Valgrind's Callgrind for
//! deterministic instruction-count metrics. Tier-1 CI gate input.

use curve25519_dalek::Scalar;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use shekyl_oxide::primitives::Commitment;
use shekyl_scanner::BalanceSummary;
use shekyl_engine_state::{transfer::SPENDABLE_AGE, TransferDetails};

fn synthetic_transfer(seed: u64, height: u64) -> TransferDetails {
    let mut tx_hash = [0u8; 32];
    tx_hash[..8].copy_from_slice(&seed.to_le_bytes());
    let mut key_bytes = [0u8; 32];
    key_bytes[..8].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let key = &Scalar::from_bytes_mod_order(key_bytes)
        * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

    TransferDetails {
        tx_hash,
        internal_output_index: seed & 0xff,
        global_output_index: seed,
        block_height: height,
        key,
        key_offset: Scalar::ZERO,
        commitment: Commitment::new(Scalar::ONE, 1_000 + seed),
        subaddress: None,
        payment_id: None,
        spent: (seed & 0x7) == 0,
        spent_height: None,
        key_image: None,
        staked: (seed & 0b11) == 0,
        stake_tier: (seed & 0x3) as u8,
        stake_lock_until: height + 100,
        last_claimed_height: 0,
        combined_shared_secret: None,
        ho: None,
        y: None,
        z: None,
        k_amount: None,
        eligible_height: height + SPENDABLE_AGE,
        frozen: (seed & 0xf) == 0,
        fcmp_precomputed_path: None,
    }
}

fn build_transfers(n: usize) -> Vec<TransferDetails> {
    (0..n as u64)
        .map(|seed| synthetic_transfer(seed, 1_000 + seed))
        .collect()
}

#[library_benchmark]
#[benches::with_setup(args = [100, 1_000, 10_000], setup = build_transfers)]
fn hot_path_bench_balance_compute(transfers: Vec<TransferDetails>) -> BalanceSummary {
    let h = 1_000 + (transfers.len() as u64) / 2;
    black_box(BalanceSummary::compute(&transfers, h))
}

library_benchmark_group!(
    name = balance;
    benchmarks = hot_path_bench_balance_compute,
);

main!(library_benchmark_groups = balance);
