// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PQC rederivation benchmark (Phase 7e).
//!
//! Benchmarks the per-output key rederivation pipeline:
//!   ML-KEM-768 decapsulation + HKDF-SHA-512 + ML-DSA-65 keygen
//!
//! Target: < 100ms per output on x86_64.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_crypto_pq::derivation::{derive_pqc_keypair, hash_pqc_public_key};
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};

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

fn bench_pqc_keypair_derivation(c: &mut Criterion) {
    let combined_ss = [0xab; 64];

    c.bench_function("pqc_keypair_derivation_hkdf_plus_ml_dsa_65_keygen", |b| {
        b.iter(|| {
            let _ = derive_pqc_keypair(black_box(&combined_ss), black_box(0)).unwrap();
        })
    });
}

fn bench_hash_pqc_public_key(c: &mut Criterion) {
    let pk_bytes = vec![0xab; 1952]; // ML-DSA-65 public key size

    c.bench_function("hash_pqc_public_key_blake2b512", |b| {
        b.iter(|| {
            let _ = hash_pqc_public_key(black_box(&pk_bytes));
        })
    });
}

fn bench_full_per_output_rederivation(c: &mut Criterion) {
    let kem = HybridX25519MlKem;
    let (pk, sk) = kem.keypair_generate().unwrap();
    let (_ss, ct) = kem.encapsulate(&pk).unwrap();

    c.bench_function("full_per_output_rederivation", |b| {
        b.iter(|| {
            // Step 1: ML-KEM-768 decapsulation
            let ss = kem.decapsulate(black_box(&sk), black_box(&ct)).unwrap();

            // Step 2: HKDF-SHA-512 + ML-DSA-65 keygen (inside derive_pqc_keypair)
            let kp = derive_pqc_keypair(black_box(&ss.0), black_box(0)).unwrap();

            // Step 3: Hash public key for leaf scalar
            let _ = hash_pqc_public_key(black_box(&kp.public_key));
        })
    });
}

criterion_group!(
    benches,
    bench_kem_decapsulate,
    bench_pqc_keypair_derivation,
    bench_hash_pqc_public_key,
    bench_full_per_output_rederivation,
);
criterion_main!(benches);
