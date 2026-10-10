// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Ed25519 + FN-DSA-1024 (hybrid scheme 3): wall clock for one nested sign
//! and one nested verify (`docs/design/FN_DSA_HYBRID.md`).
//!
//! The sign arm is the production entry, [`SignatureScheme::sign`], with its
//! OS-seeded hedged draw; FN-DSA signing is rejection sampling, so its time
//! is a distribution and this arm reports it as one. The instruction-count
//! sibling (`fn_dsa_hybrid_iai`) pins the draw instead.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSecretKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};

/// A receipt-sized message: the serve-credit receipt body is a few fixed
/// fields, and the combiner hashes the message to 64 bytes before either
/// half signs, so the length moves only the cSHAKE absorb.
const MESSAGE: [u8; 128] = [0xA5; 128];
const ED25519_SEED: [u8; 32] = [0x11; 32];
const FN_DSA_SEED: [u8; 32] = [0x22; 32];
/// Pins FN-DSA's signing draw, and with it the number of rejection-sampling
/// rounds, so the measured path is the same on every run.
const SIGN_RNG_SEED: [u8; 32] = [0x33; 32];

fn keypair() -> (FnDsaHybridPublicKey, FnDsaHybridSecretKey) {
    HybridEd25519FnDsa::keypair_from_seeds(&ED25519_SEED, &FN_DSA_SEED).expect("seeded keygen")
}

fn signed() -> (FnDsaHybridPublicKey, FnDsaHybridSignature) {
    let (public, secret) = keypair();
    let signature = HybridEd25519FnDsa
        .sign_with_rng_seed(&secret, SCHEME_DOMAIN_RECEIPT, &MESSAGE, &SIGN_RNG_SEED)
        .expect("seeded sign");
    (public, signature)
}

fn bench_sign(c: &mut Criterion) {
    let (_public, secret) = keypair();
    c.bench_function("fn_dsa_hybrid_sign", |b| {
        b.iter(|| {
            HybridEd25519FnDsa
                .sign(
                    black_box(&secret),
                    SCHEME_DOMAIN_RECEIPT,
                    black_box(&MESSAGE),
                )
                .expect("sign")
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let (public, signature) = signed();
    c.bench_function("fn_dsa_hybrid_verify", |b| {
        b.iter(|| {
            HybridEd25519FnDsa
                .verify(
                    black_box(&public),
                    SCHEME_DOMAIN_RECEIPT,
                    black_box(&MESSAGE),
                    black_box(&signature),
                )
                .expect("verify")
        })
    });
}

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("fn_dsa_hybrid_keygen_from_seeds", |b| {
        b.iter(|| {
            HybridEd25519FnDsa::keypair_from_seeds(
                black_box(&ED25519_SEED),
                black_box(&FN_DSA_SEED),
            )
            .expect("seeded keygen")
        })
    });
}

criterion_group!(benches, bench_sign, bench_verify, bench_keygen);
criterion_main!(benches);
