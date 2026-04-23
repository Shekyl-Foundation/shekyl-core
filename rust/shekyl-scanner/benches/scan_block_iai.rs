// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/scan_block.rs`.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use shekyl_oxide::primitives::Commitment;
use shekyl_scanner::{
    output::WalletOutput,
    runtime_ext::WalletStateExt,
    scan::{RecoveredWalletOutput, Timelocked},
    RuntimeWalletState,
};

fn unique_point(seed: u64) -> curve25519_dalek::EdwardsPoint {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    &Scalar::from_bytes_mod_order(bytes) * ED25519_BASEPOINT_TABLE
}

fn build_state_and_outputs(k: usize) -> (RuntimeWalletState, Timelocked) {
    let tx_hash = [0x42u8; 32];
    let recovered: Vec<RecoveredWalletOutput> = (0..k as u64)
        .map(|i| {
            let wo = WalletOutput::new_for_test(
                tx_hash,
                i,
                1_000 + i,
                unique_point(1_000 + i),
                Scalar::ZERO,
                Commitment::new(Scalar::ONE, 1_000 + i),
                None,
            );
            RecoveredWalletOutput::new_for_test(wo, 1_000 + i)
        })
        .collect();
    (RuntimeWalletState::new(), Timelocked::from_vec(recovered))
}

#[library_benchmark]
#[benches::with_setup(args = [0, 5, 50], setup = build_state_and_outputs)]
fn hot_path_bench_scan_block_process_outputs(
    input: (RuntimeWalletState, Timelocked),
) -> RuntimeWalletState {
    let (mut ws, outputs) = input;
    let added = ws.process_scanned_outputs(2_000, [0xAAu8; 32], outputs);
    black_box(added);
    ws
}

library_benchmark_group!(
    name = scan_block;
    benchmarks = hot_path_bench_scan_block_process_outputs,
);

main!(library_benchmark_groups = scan_block);
