// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Ed25519 + FN-DSA-1024 (hybrid scheme 3): instruction counts for one
//! nested sign and one nested verify (`docs/design/FN_DSA_HYBRID.md`).
//!
//! The sign arm goes through `sign_with_rng_seed`, which shares the nested
//! body with [`SignatureScheme::sign`] and differs only in where FN-DSA's
//! signer draws from: a fixed ChaCha20 stream, so the rejection-sampling
//! trajectory, and the count, is the same on every run. The count is that of
//! the code path the runner's CPU selects; the pinned crate dispatches to
//! AVX2 at run time where it is present.

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

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

#[library_benchmark]
#[bench::receipt(setup = keypair)]
fn crypto_bench_fn_dsa_hybrid_sign(keys: (FnDsaHybridPublicKey, FnDsaHybridSecretKey)) {
    let (_public, secret) = keys;
    let signature = HybridEd25519FnDsa
        .sign_with_rng_seed(
            black_box(&secret),
            SCHEME_DOMAIN_RECEIPT,
            black_box(&MESSAGE),
            black_box(&SIGN_RNG_SEED),
        )
        .expect("seeded sign");
    black_box(signature);
}

#[library_benchmark]
#[bench::receipt(setup = signed)]
fn crypto_bench_fn_dsa_hybrid_verify(signed: (FnDsaHybridPublicKey, FnDsaHybridSignature)) {
    let (public, signature) = signed;
    HybridEd25519FnDsa
        .verify(
            black_box(&public),
            SCHEME_DOMAIN_RECEIPT,
            black_box(&MESSAGE),
            black_box(&signature),
        )
        .expect("verify");
}

library_benchmark_group!(
    name = fn_dsa_hybrid;
    benchmarks =
        crypto_bench_fn_dsa_hybrid_sign,
        crypto_bench_fn_dsa_hybrid_verify,
);

main!(library_benchmark_groups = fn_dsa_hybrid);
