// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hardening-pass commit 2 (§3.2): cold-open of a `.wallet.keys` + `.wallet` pair.
//!
//! Measures the UI-visible wait the user experiences between "I
//! clicked Open" and "the ledger is loaded": Argon2id password wrap,
//! keys-file AEAD decrypt, state-file AEAD decrypt, postcard
//! deserialization of the `WalletLedger`.
//!
//! This is the Rust-side counterpart to
//! `tests/wallet_bench/bench_wallet2.cpp::BM_open_cold` (currently
//! skipped — see `docs/MID_REWIRE_HARDENING.md` §3.1 "known gaps").
//! Once the C++ regression is fixed, the two benchmarks together gate
//! the "open stayed snappy across the rewire" claim.
//!
//! Naming convention: `crypto_bench_*` — bidirectional threshold. A
//! speedup is just as suspicious as a slowdown because the wrap path
//! runs Argon2id; a sudden halving of cost likely means a parameter
//! regression (e.g. silent `m_log2` demotion), not a win.
//!
//! The `create`-phase cost is unavoidably captured by the fixture
//! builder but excluded from the measured region (the criterion
//! harness only times `::open`). The iai-callgrind sibling
//! (`open_iai.rs`) runs under a KAT Argon2 profile because Valgrind
//! would otherwise balloon per-iteration cost to tens of minutes; see
//! the manifest for the un-skip criteria if the default profile
//! becomes feasible.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use tempfile::TempDir;

use shekyl_address::Network;
use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
use shekyl_crypto_pq::wallet_envelope::{
    CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_wallet_file::{CreateParams, SafetyOverrides, WalletFile};
use shekyl_wallet_state::WalletLedger;

const BENCH_NETWORK: Network = Network::Testnet;
const BENCH_PASSWORD: &[u8] = b"correct horse battery staple";

/// Minimal fixture: `ViewOnly` capability with deterministic contents.
/// The envelope does not interpret these bytes beyond length, so they
/// are sufficient for measuring the framing + AEAD + Argon2id cost
/// that `open_cold` actually exercises.
struct Fixture {
    view_sk: [u8; 32],
    ml_kem_dk: [u8; ML_KEM_768_DK_LEN],
    spend_pk: [u8; 32],
    address: [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
}

impl Fixture {
    fn new() -> Self {
        Self {
            view_sk: [0x11; 32],
            ml_kem_dk: [0x22; ML_KEM_768_DK_LEN],
            spend_pk: [0x33; 32],
            address: {
                let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
                a[0] = 0x01;
                a
            },
        }
    }

    fn capability(&self) -> CapabilityContent<'_> {
        CapabilityContent::ViewOnly {
            view_sk: &self.view_sk,
            ml_kem_dk: &self.ml_kem_dk,
            spend_pk: &self.spend_pk,
        }
    }
}

/// Prepare a fresh on-disk wallet pair and return its `base` path plus
/// the tempdir (kept alive for the lifetime of the returned tuple so
/// the files do not get cleaned out from under the bench).
fn prepared_wallet(kdf: KdfParams) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().join("bench.wallet");
    let fx = Fixture::new();
    let cap = fx.capability();
    let ledger = WalletLedger::empty();
    let params = CreateParams {
        base_path: &base,
        password: BENCH_PASSWORD,
        network: BENCH_NETWORK,
        seed_format: 0x00,
        capability: &cap,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 0,
        expected_classical_address: &fx.address,
        kdf,
        initial_ledger: &ledger,
    };
    {
        let _handle = WalletFile::create(&params).expect("create");
        // Handle drops here, releasing the advisory lock so the bench
        // body's `::open` call can reacquire it.
    }
    (dir, base)
}

fn crypto_bench_wallet_open_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bench_wallet_open_cold");
    // Argon2id at 64 MiB, t=3, p=1 takes ~300–600 ms on a modern
    // laptop. Cap measurement to keep the bench run tractable while
    // still crossing criterion's minimum-samples threshold.
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(30));

    let kdf = KdfParams::default();
    group.bench_function("default_kdf", |b| {
        b.iter_batched(
            || prepared_wallet(kdf),
            |(_dir, base)| {
                let (handle, outcome) = WalletFile::open(
                    black_box(&base),
                    black_box(BENCH_PASSWORD),
                    BENCH_NETWORK,
                    SafetyOverrides::none(),
                )
                .expect("open");
                black_box((handle, outcome));
            },
            criterion::BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(benches, crypto_bench_wallet_open_cold);
criterion_main!(benches);
