// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! gungraun companion to `benches/balance.rs`.
//!
//! Same workload (build N synthetic `TransferDetails`, compute
//! `BalanceSummary`) measured via Valgrind's Callgrind for
//! deterministic instruction-count metrics. Tier-1 CI gate input.

// This bench measures `BalanceSummary::compute` and nothing else. `compute`
// borrows `&[TransferDetails]`; production never drops the transfers on this
// path (the ledger owns them, they are wiped once at wallet teardown). The
// fixture is therefore RETURNED from the bench fn so its teardown is charged
// to the harness, OUTSIDE the measured region — the `scan_block_iai` idiom.
//
// This matters because `TransferDetails` is zeroize-on-drop and the zeroize
// crate's per-field volatile writes are deliberately un-elidable. Measuring
// the by-value drop instead made this a "zeroize N `TransferDetails`" bench
// (~95% of the instruction count was the drop, not `compute`), so it tripped
// the +15% `hot_path` gate on every field ever added to `TransferDetails`
// (F14's `awaiting_confirmation` being the latest) rather than on real
// balance-compute regressions.
//
// `gungraun-macros` does not auto-suppress `needless_pass_by_value` on the
// generated wrapper the way `iai-callgrind-macros` did, so allow it explicitly.
#![allow(clippy::needless_pass_by_value)]

use curve25519_dalek::Scalar;
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use shekyl_curve_primitives::Commitment;
use shekyl_engine_state::{transfer::SPENDABLE_AGE, TransferDetails};
use shekyl_scanner::BalanceSummary;

fn synthetic_transfer(seed: u64, height: u64) -> TransferDetails {
    let mut tx_hash = [0u8; 32];
    tx_hash[..8].copy_from_slice(&seed.to_le_bytes());
    let mut key_bytes = [0u8; 32];
    key_bytes[..8].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let key = &Scalar::from_bytes_mod_order(key_bytes)
        * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

    TransferDetails {
        tx_hash: shekyl_types::TxHash::from_bytes(tx_hash),
        internal_output_index: seed & 0xff,
        global_output_index: seed,
        block_height: height,
        key,
        key_offset: Scalar::ZERO,
        commitment: Commitment::new(Scalar::ONE, 1_000 + seed),
        payment_id: None,
        spent: (seed & 0x7) == 0,
        spent_height: None,
        key_image: None,
        awaiting_confirmation: None,
        source_ciphertext: None,
        output_handle: None,
        eligible_height: height + SPENDABLE_AGE,
        frozen: (seed & 0xf) == 0,
        fcmp_precomputed_path: None,
        receive_attribution: shekyl_engine_state::ReceiveAttribution::default(),
    }
}

fn build_transfers(n: usize) -> Vec<TransferDetails> {
    (0..n as u64)
        .map(|seed| synthetic_transfer(seed, 1_000 + seed))
        .collect()
}

#[library_benchmark]
#[benches::with_setup(args = [100, 1_000, 10_000], setup = build_transfers)]
fn hot_path_bench_balance_compute(
    transfers: Vec<TransferDetails>,
) -> (BalanceSummary, Vec<TransferDetails>) {
    let h = 1_000 + (transfers.len() as u64) / 2;
    let summary = black_box(BalanceSummary::compute(&transfers, h));
    // Return the fixture: its zeroize-on-drop teardown must be charged to the
    // harness, not the measured region (see the module comment).
    (summary, transfers)
}

library_benchmark_group!(
    name = balance;
    benchmarks = hot_path_bench_balance_compute,
);

main!(library_benchmark_groups = balance);
