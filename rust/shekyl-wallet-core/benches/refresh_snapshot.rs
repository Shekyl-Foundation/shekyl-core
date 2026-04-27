// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Snapshot-clone regression benchmark for `Wallet::refresh`.
//!
//! Phase 2a's snapshot strategy is **clone-not-Arc**: every retry of
//! the snapshot-merge loop pulls a fresh [`LedgerSnapshot`] by copying
//! `synced_height` (`u64`) and the bounded
//! `reorg_blocks: ReorgBlocks` (capped at the persistence-layer
//! `DEFAULT_REORG_BLOCKS_CAPACITY`, currently 10 entries of 40 bytes
//! each). The wallet's `transfers` vec is deliberately **not**
//! snapshotted — the producer collects every spend-side key image
//! unfiltered and `apply_scan_result_to_state` does the actual
//! matching against the live (post-lock) state.
//!
//! This benchmark exists to regression-gate that decision: it
//! constructs a [`LedgerBlock`] populated with `{1_000, 10_000,
//! 50_000}` transfers and measures `LedgerSnapshot::from_ledger(...)`
//! followed by `.clone()`. If any future refactor accidentally pulls
//! `transfers` (or another size-`O(wallet)` field) into the snapshot,
//! this benchmark surfaces the dependency: the curve over `N` will
//! tilt instead of staying flat.
//!
//! # Pass / fail signal
//!
//! The "phase 2a target" the plan named is a sub-millisecond median
//! at every size. Criterion does not enforce hard thresholds itself;
//! review the printed `time:` line on each bench. The intent is to
//! flag any run whose median exceeds 1ms — that is the threshold
//! beyond which `RefreshHandle`'s per-retry cost would start to
//! dominate the producer's actual scan work, and the strategy would
//! need to flip to `Arc<LedgerSnapshot>` per the FOLLOWUP item already
//! pinned in `LedgerSnapshot`'s docstring.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_oxide::primitives::Commitment;
use shekyl_wallet_core::__bench_internals::LedgerSnapshot;
use shekyl_wallet_state::{
    payment_id::PaymentId,
    subaddress::SubaddressIndex,
    transfer::{TransferDetails, SPENDABLE_AGE},
    BlockchainTip, LedgerBlock, ReorgBlocks,
};
use zeroize::Zeroizing;

/// Mirrors `shekyl-wallet-state::ledger_block::tests::sample_transfer`
/// — the canonical "lightweight transfer for tests" shape. Reproduced
/// here because the test helper is `cfg(test)` inside a different
/// crate. Keep this in lockstep if the test helper grows new fields:
/// drift between bench and test would let snapshot-cost regressions
/// hide behind shape mismatches.
fn sample_transfer(seed: u64) -> TransferDetails {
    let lo = (seed & 0xff) as u8;
    TransferDetails {
        tx_hash: [lo; 32],
        internal_output_index: seed,
        global_output_index: 1_000 + seed,
        block_height: 100,
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: Commitment::new(Scalar::ONE, 1_000_000 + seed),
        subaddress: Some(SubaddressIndex::new((seed & 0xffff_ffff) as u32)),
        payment_id: Some(PaymentId([lo; 8])),
        spent: false,
        spent_height: None,
        key_image: Some([lo ^ 0xFF; 32]),
        staked: false,
        stake_tier: 0,
        stake_lock_until: 0,
        last_claimed_height: 0,
        combined_shared_secret: Some(Zeroizing::new([lo.wrapping_add(1); 64])),
        ho: Some(Zeroizing::new([lo.wrapping_add(2); 32])),
        y: Some(Zeroizing::new([lo.wrapping_add(3); 32])),
        z: Some(Zeroizing::new([lo.wrapping_add(4); 32])),
        k_amount: Some(Zeroizing::new([lo.wrapping_add(5); 32])),
        eligible_height: 100 + SPENDABLE_AGE,
        frozen: false,
        fcmp_precomputed_path: None,
    }
}

/// Build a [`LedgerBlock`] with `n` transfers, a fixed 10-entry reorg
/// window, and an arbitrary tip. The reorg window matches
/// `shekyl-wallet-state`'s `DEFAULT_REORG_BLOCKS_CAPACITY` so the bench
/// reflects the snapshot a real wallet would produce; the transfer
/// count varies to demonstrate the clone-cost decoupling.
fn build_ledger(n: usize) -> LedgerBlock {
    let mut transfers = Vec::with_capacity(n);
    for i in 0..n {
        transfers.push(sample_transfer(i as u64));
    }
    let tip = BlockchainTip::new(1_000_000, [0xAA; 32]);
    let reorg_blocks = ReorgBlocks {
        blocks: (999_990..=1_000_000)
            .map(|h| (h, [(h & 0xff) as u8; 32]))
            .collect(),
    };
    LedgerBlock::new(transfers, tip, reorg_blocks)
}

fn bench_snapshot_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_snapshot_clone");
    for &n in &[1_000usize, 10_000, 50_000] {
        let ledger = build_ledger(n);
        let snapshot = LedgerSnapshot::from_ledger_for_bench(&ledger);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("clone", n), &snapshot, |b, snap| {
            b.iter(|| {
                let cloned = black_box(snap.clone());
                black_box(cloned)
            })
        });
    }
    group.finish();
}

fn bench_snapshot_from_ledger(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_snapshot_from_ledger");
    for &n in &[1_000usize, 10_000, 50_000] {
        let ledger = build_ledger(n);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("from_ledger", n), &ledger, |b, ledger| {
            b.iter(|| {
                let snap = black_box(LedgerSnapshot::from_ledger_for_bench(ledger));
                black_box(snap)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_snapshot_clone, bench_snapshot_from_ledger);
criterion_main!(benches);
