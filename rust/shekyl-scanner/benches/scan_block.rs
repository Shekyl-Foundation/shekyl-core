// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hardening-pass commit 2 (§3.2): scanner ingestion per block.
//!
//! Measures the non-crypto bookkeeping half of the scanner pipeline:
//! `RuntimeWalletState::process_scanned_outputs` ingesting `K`
//! synthetic `RecoveredWalletOutput`s for a single block. The
//! cryptographic half — `scan_output_recover` (X25519 view-tag
//! pre-filter + ML-KEM-768 decap + HKDF + leaf-hash rederivation) —
//! lives in `shekyl-crypto-pq/benches/pqc_rederivation.rs`; the two
//! together span the "owned output lands in wallet state" pipeline.
//!
//! K values (0, 5, 50) match the C++ spec's intended sweep (see
//! `tests/wallet_bench/bench_wallet2.cpp` — currently not wired for
//! `BM_scan_block_K` because C++ `wallet2::scan` is daemon-coupled;
//! this bench is Rust-only as planned in §3.1).
//!
//! Naming convention: `hot_path_bench_*` — slowdown-only threshold.
//! No crypto primitives in the measured region.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};

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

fn build_owned_outputs(k: usize) -> Timelocked {
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
    Timelocked::from_vec(recovered)
}

const OWNED_COUNTS: &[usize] = &[0, 5, 50];

fn hot_path_bench_scan_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path_bench_scan_block");
    for &k in OWNED_COUNTS {
        group.throughput(Throughput::Elements(k.max(1) as u64));
        group.bench_with_input(
            BenchmarkId::new("process_scanned_outputs", k),
            &k,
            |b, &k| {
                b.iter_batched(
                    || (RuntimeWalletState::new(), build_owned_outputs(k)),
                    |(mut ws, outputs)| {
                        let added = ws.process_scanned_outputs(
                            black_box(2_000),
                            black_box([0xAAu8; 32]),
                            outputs,
                        );
                        black_box((ws, added));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, hot_path_bench_scan_block);
criterion_main!(benches);
