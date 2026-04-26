// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/ledger.rs`.
//!
//! Same workload (build a `WalletLedger` with N synthetic transfers,
//! round-trip through postcard) measured via Valgrind's Callgrind for
//! deterministic instruction-count metrics. This is the Tier-1 metric
//! the CI gate in `docs/MID_REWIRE_HARDENING.md` §3.3 will enforce.
//!
//! Requires `cargo install iai-callgrind-runner` and a working Valgrind
//! install. The criterion sibling bench (`ledger.rs`) is the
//! wall-clock story; this file is the "same machine, two runs,
//! agree to the instruction" story.

use curve25519_dalek::Scalar;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use shekyl_oxide::primitives::Commitment;
use shekyl_wallet_state::{
    transfer::SPENDABLE_AGE, BlockchainTip, LedgerBlock, TransferDetails, WalletLedger,
};

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
        spent: false,
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
        frozen: false,
        fcmp_precomputed_path: None,
    }
}

fn build_ledger(n: usize) -> WalletLedger {
    let mut w = WalletLedger::empty();
    let transfers: Vec<TransferDetails> = (0..n as u64)
        .map(|seed| synthetic_transfer(seed, 1_000 + seed))
        .collect();
    // See `benches/ledger.rs::build_ledger` for the I-1 invariant
    // rationale. The criterion sibling and this iai-callgrind harness
    // share the same tip-pinning requirement; the deserialize bench
    // below would otherwise panic out of Valgrind with the same
    // `tip-height-not-below-transfer` shape.
    let tip_height = transfers.iter().map(|t| t.block_height).max().unwrap_or(0);
    w.ledger = LedgerBlock {
        block_version: w.ledger.block_version,
        transfers,
        tip: BlockchainTip {
            synced_height: tip_height,
            tip_hash: Some([0xAB; 32]),
        },
        reorg_blocks: w.ledger.reorg_blocks.clone(),
    };
    w
}

fn build_bytes(n: usize) -> Vec<u8> {
    build_ledger(n).to_postcard_bytes().expect("serialize")
}

#[library_benchmark]
#[benches::with_setup(args = [100, 1_000, 10_000], setup = build_ledger)]
fn hot_path_bench_ledger_postcard_serialize(ledger: WalletLedger) -> Vec<u8> {
    black_box(ledger.to_postcard_bytes().expect("serialize"))
}

#[library_benchmark]
#[benches::with_setup(args = [100, 1_000, 10_000], setup = build_bytes)]
fn hot_path_bench_ledger_postcard_deserialize(bytes: Vec<u8>) -> WalletLedger {
    black_box(WalletLedger::from_postcard_bytes(&bytes).expect("deserialize"))
}

library_benchmark_group!(
    name = ledger;
    benchmarks =
        hot_path_bench_ledger_postcard_serialize,
        hot_path_bench_ledger_postcard_deserialize,
);

main!(library_benchmark_groups = ledger);
