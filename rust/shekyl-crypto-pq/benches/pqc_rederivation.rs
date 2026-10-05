// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PQC rederivation benchmark.
//!
//! Benchmarks the per-output key rederivation pipeline:
//!   ML-KEM-768 decapsulation + HKDF-SHA-512 + ML-DSA-65 keygen + leaf hash
//!
//! Target: < 100ms per output on x86_64.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_crypto_pq::leaf_commitment::{derive_pqc_leaf, pqc_key_scalar};

fn bench_kem_decapsulate(c: &mut Criterion) {
    let kem = HybridX25519MlKem;
    let (pk, sk) = kem.keypair_generate().unwrap();
    let (_ss, ct) = kem.encapsulate(&pk).unwrap();

    c.bench_function("ml_kem_768_decapsulate", |b| {
        b.iter(|| {
            let _ = kem.decapsulate(black_box(&sk), black_box(&ct)).unwrap();
        })
    });
}

fn bench_pqc_leaf_derivation(c: &mut Criterion) {
    let combined_ss = [0xab; 64];

    c.bench_function("pqc_leaf_hash_derivation_hkdf_keygen_hash", |b| {
        b.iter(|| {
            let _ = derive_pqc_leaf(black_box(&combined_ss), black_box(0)).unwrap();
        })
    });
}

fn bench_pqc_key_scalar(c: &mut Criterion) {
    let pk_bytes = vec![0xab; 1952]; // ML-DSA-65 public key size

    c.bench_function("pqc_key_scalar_cshake256", |b| {
        b.iter(|| {
            let _ = pqc_key_scalar(black_box(&pk_bytes));
        })
    });
}

fn bench_full_per_output_rederivation(c: &mut Criterion) {
    let kem = HybridX25519MlKem;
    let (pk, sk) = kem.keypair_generate().unwrap();
    let (_ss, ct) = kem.encapsulate(&pk).unwrap();

    c.bench_function("full_per_output_rederivation", |b| {
        b.iter(|| {
            let ss = kem.decapsulate(black_box(&sk), black_box(&ct)).unwrap();
            let _ = derive_pqc_leaf(black_box(&ss.0), black_box(0)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_kem_decapsulate,
    bench_pqc_leaf_derivation,
    bench_pqc_key_scalar,
    bench_full_per_output_rederivation,
);
criterion_main!(benches);
