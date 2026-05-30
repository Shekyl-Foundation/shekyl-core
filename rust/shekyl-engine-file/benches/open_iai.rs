// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/open.rs`.
//!
//! Runs a cold `WalletFile::open` under Valgrind's Callgrind
//! with the KAT Argon2 profile (`m_log2 = 0x08` = 256 KiB, t=1, p=1).
//! Production `KdfParams::default()` (64 MiB, t=3) would make each
//! Valgrind-instrumented iteration take tens of minutes; this profile
//! exercises the same control flow in a fraction of the time while
//! still crossing every code path the deterministic metric covers.
//! See the manifest (`docs/benchmarks/shekyl_rust_v0.manifest.md` §2)
//! for the cross-stack interpretation rule.

use std::path::PathBuf;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use tempfile::TempDir;

use shekyl_address::Network;
use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
use shekyl_crypto_pq::wallet_envelope::{
    CapabilityContent, KdfParams, EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_engine_file::{CreateParams, SafetyOverrides, WalletFile};
use shekyl_engine_state::WalletLedger;

const BENCH_NETWORK: Network = Network::Testnet;
const BENCH_PASSWORD: &[u8] = b"correct horse battery staple";

fn prepared_wallet() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().join("bench.wallet");
    let view_sk = [0x11u8; 32];
    let ml_kem_dk = [0x22u8; ML_KEM_768_DK_LEN];
    let spend_pk = [0x33u8; 32];
    let mut address = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
    address[0] = 0x01;

    let cap = CapabilityContent::ViewOnly {
        view_sk: &view_sk,
        ml_kem_dk: &ml_kem_dk,
        spend_pk: &spend_pk,
    };
    let ledger = WalletLedger::empty();
    let params = CreateParams {
        base_path: &base,
        password: BENCH_PASSWORD,
        network: BENCH_NETWORK,
        seed_format: 0x00,
        capability: &cap,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 0,
        expected_classical_address: &address,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        initial_ledger: &ledger,
    };
    {
        let _handle = WalletFile::create(&params).expect("create");
    }
    (dir, base)
}

#[library_benchmark]
#[bench::kat_kdf(setup = prepared_wallet)]
fn crypto_bench_wallet_open_cold(prepared: (TempDir, PathBuf)) {
    let (dir, base) = prepared;
    let (handle, outcome) = WalletFile::open(
        black_box(&base),
        black_box(BENCH_PASSWORD),
        BENCH_NETWORK,
        SafetyOverrides::none(),
    )
    .expect("open");
    black_box((handle, outcome, dir));
}

library_benchmark_group!(
    name = open_cold;
    benchmarks = crypto_bench_wallet_open_cold,
);

main!(library_benchmark_groups = open_cold);
