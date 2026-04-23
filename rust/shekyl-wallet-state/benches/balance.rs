// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hardening-pass commit 2 (§3.2): `BalanceSummary::compute` over N transfers.
//!
//! Direct counterpart to `tests/wallet_bench/bench_wallet2.cpp::BM_balance_compute`.
//! Measures the linear-in-N walk that categorizes each `TransferDetails`
//! as unlocked / locked-by-timelock / staked_total / staked_matured /
//! staked_locked / frozen. This is the wallet UI's refresh cost after
//! every block; a drift from O(n) to O(n log n) lands here first.
//!
//! The canonical balance implementation lives in `shekyl-scanner`; the
//! bench is hosted here (in `shekyl-wallet-state`) because the
//! `TransferDetails` fixture builder is already in this crate and
//! duplicating it in `shekyl-scanner/benches/` would split the fixture
//! source of truth. `shekyl-scanner` is a dev-dep.
//!
//! Naming convention (see `docs/MID_REWIRE_HARDENING.md` §3.2):
//! `hot_path_bench_*` — slowdown-only threshold.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use curve25519_dalek::Scalar;

use shekyl_oxide::primitives::Commitment;
use shekyl_scanner::BalanceSummary;
use shekyl_wallet_state::{transfer::SPENDABLE_AGE, TransferDetails};

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

/// Sizes mirroring `BM_balance_compute` in the C++ harness so the
/// cross-stack delta is directly comparable.
const SIZES: &[usize] = &[100, 1_000, 10_000];

fn hot_path_bench_balance_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path_bench_balance_compute");
    for &n in SIZES {
        let transfers = build_transfers(n);
        // `current_height` chosen so ~50% of timelocks are satisfied,
        // matching the C++ fixture's "balanced" classification spread.
        let current_height = 1_000 + (n as u64) / 2;
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &transfers, |b, transfers| {
            b.iter(|| black_box(BalanceSummary::compute(black_box(transfers), current_height)));
        });
    }
    group.finish();
}

criterion_group!(benches, hot_path_bench_balance_compute);
criterion_main!(benches);
