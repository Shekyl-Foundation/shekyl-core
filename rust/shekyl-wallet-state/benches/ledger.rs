// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hardening-pass commit 2 (§3.2): `WalletLedger` postcard round-trip.
//!
//! This bench measures the cost of serializing a `WalletLedger` whose
//! `ledger.transfers` vector carries `N` synthetic transfers, then
//! deserializing the resulting bytes back through the version-gated
//! `from_postcard_bytes` path. Covers the same bytes that
//! `shekyl-wallet-file`'s `save_state` hands to the envelope's
//! `seal_state_file`, minus the AEAD itself. This is the canary for
//! postcard-layer regressions — an O(n²) drift in serde, a field
//! reorder that widens the on-wire blob, an added `#[serde(default)]`
//! that blows up decode time — all land here first.
//!
//! The bench lives in `shekyl-wallet-state` (not `shekyl-wallet-file`)
//! because the postcard round-trip is a property of the *payload*
//! types; the file crate's job is AEAD + atomic writes.
//!
//! Naming convention per `docs/MID_REWIRE_HARDENING.md` §3.2:
//! `hot_path_bench_*` — slowdown-only threshold. Speedups are
//! unambiguously good here (no crypto primitives touched).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use curve25519_dalek::Scalar;

use shekyl_oxide::primitives::Commitment;
use shekyl_wallet_state::{transfer::SPENDABLE_AGE, LedgerBlock, TransferDetails, WalletLedger};

/// Build a deterministic synthetic `TransferDetails` at `(seed, height)`.
///
/// All Zeroizing/HKDF fields are left `None` because the postcard cost
/// we care about is the aggregate over the common, non-optional
/// fields; the optional secret fields contribute a handful of bytes
/// each when `Some` and the same presence-tag byte when `None`. The
/// manifest (§3.2) records this choice so the delta against C++ is
/// interpretable.
fn synthetic_transfer(seed: u64, height: u64) -> TransferDetails {
    let mut tx_hash = [0u8; 32];
    tx_hash[..8].copy_from_slice(&seed.to_le_bytes());

    let mut key_bytes = [0u8; 32];
    key_bytes[..8].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let key_scalar = Scalar::from_bytes_mod_order(key_bytes);
    let key = &key_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

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
    w.ledger = LedgerBlock {
        block_version: w.ledger.block_version,
        transfers,
        tip: w.ledger.tip.clone(),
        reorg_blocks: w.ledger.reorg_blocks.clone(),
    };
    w
}

/// Sizes mirroring `tests/wallet_bench/bench_wallet2.cpp`'s
/// `BM_balance_compute` parameter sweep so the cross-stack delta
/// (Rust `postcard` vs C++ `boost::serialization`, currently skipped
/// per §3.1) is directly comparable.
const SIZES: &[usize] = &[100, 1000, 10000];

fn hot_path_bench_ledger_postcard_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path_bench_ledger_postcard_roundtrip");
    for &n in SIZES {
        let ledger = build_ledger(n);
        let bytes = ledger.to_postcard_bytes().expect("serialize fixture");
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("serialize", n), &ledger, |b, ledger| {
            b.iter(|| black_box(ledger.to_postcard_bytes().expect("serialize")));
        });
        group.bench_with_input(BenchmarkId::new("deserialize", n), &bytes, |b, bytes| {
            b.iter(|| {
                black_box(WalletLedger::from_postcard_bytes(black_box(bytes)).expect("deserialize"))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, hot_path_bench_ledger_postcard_roundtrip);
criterion_main!(benches);
