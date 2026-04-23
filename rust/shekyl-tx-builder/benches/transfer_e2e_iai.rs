// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/transfer_e2e.rs`.
//!
//! Measures the same two components (BP+ 2-output range proof and one
//! hybrid Ed25519 + ML-DSA-65 signature) under Valgrind's Callgrind
//! for deterministic instruction-count metrics.
//!
//! **Scope caveat** from the criterion sibling applies: full
//! `sign_transaction` is not exercised — FCMP++ membership proof is
//! tracked as a known gap in the manifest
//! (`docs/benchmarks/shekyl_rust_v0.manifest.md` §6.1).
//!
//! **Determinism note (§6.3 of the manifest).** This bench intentionally
//! **bypasses `HybridEd25519MlDsa::sign`** and inlines the two sign
//! steps with deterministic RNG sources, because the production
//! wrapper calls `fips204::ml_dsa_65::PrivateKey::try_sign` which
//! internally draws from `OsRng` for the ML-DSA-65 rejection-sampling
//! loop. The number of rejection iterations is variance-heavy across
//! runs (observed ~16% instruction-count drift on a clean machine),
//! which violates the iai-callgrind exit criterion from
//! `docs/MID_REWIRE_HARDENING.md` §3.2 ("two runs back-to-back agree
//! to the instruction"). FIPS 204 permits a deterministic-seed
//! variant (`try_sign_with_seed`) that exercises the same code path
//! with a fixed rejection-sampling trajectory; using it here gives
//! instruction-level stability at the cost of not measuring the
//! OsRng call itself (a rand_core::fill_bytes, negligible against the
//! multi-MI cost of the signer). The criterion sibling keeps the
//! production path (`scheme.sign(..)`) because wall-clock averaging
//! absorbs the variance; only the instruction-count metric needs
//! this treatment. The BP+ side is deterministic by construction
//! (no rejection sampling), but also uses a seeded RNG here as
//! defense in depth — so both iai sub-benches are hermetic.

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer as _, SigningKey, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as _, Signer as _};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::signature::{HybridSecretKey, HybridSignature, ML_DSA_65_SECRET_KEY_LENGTH};
use shekyl_primitives::Commitment;

/// Fixed seed for all deterministic RNG draws in this bench. The
/// value has no cryptographic meaning; it is pinned so re-runs produce
/// byte-identical fixtures. Mirrors the pinned-seed convention from
/// the C++ harness (`0xBEEFF00DCAFEBABE`), expanded to 32 bytes by
/// repeating the same little-endian stride four times.
const BENCH_SEED: [u8; 32] = [
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
];

fn seeded_rng() -> StdRng {
    StdRng::from_seed(BENCH_SEED)
}

fn fresh_2out_commitments() -> Vec<Commitment> {
    let mut rng = seeded_rng();
    let recipient = Commitment::new(Scalar::random(&mut rng), rng.next_u64());
    let change = Commitment::new(Scalar::random(&mut rng), rng.next_u64());
    vec![recipient, change]
}

/// Produce a deterministic hybrid secret key in the same byte layout
/// that `HybridEd25519MlDsa::keypair_generate` emits
/// (`ed25519 = 32 B raw secret`, `ml_dsa = ML_DSA_65_SECRET_KEY_LENGTH B`),
/// paired with the 32-byte message under sign.
///
/// The ML-DSA-65 secret's `s1, s2` vectors influence the number of
/// rejection iterations `try_sign_with_seed` needs — a random key
/// would re-introduce the very variance the seeded signing nonce was
/// meant to remove. Using a seeded `StdRng` for keygen pins both the
/// key material *and* the rejection-sampling trajectory, giving
/// instruction-level stability across runs.
fn seeded_signing_state() -> (HybridSecretKey, [u8; 32]) {
    let mut rng = seeded_rng();
    // ── Ed25519 seed: 32 fresh bytes from the seeded RNG. Equivalent
    //    to `SigningKey::generate(&mut rng)` but spelled out so the
    //    raw-bytes secret layout matches `HybridSecretKey::ed25519`.
    let mut ed25519_secret = [0u8; ED25519_SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut ed25519_secret);
    // Exercise the SigningKey round-trip so we catch an encoding
    // regression in the bench setup rather than the measured region.
    let signing_key = SigningKey::from_bytes(&ed25519_secret);
    debug_assert_eq!(signing_key.to_bytes(), ed25519_secret);

    let (_ml_dsa_public, ml_dsa_secret) =
        ml_dsa_65::try_keygen_with_rng(&mut rng).expect("ml-dsa seeded keygen");

    let sk = HybridSecretKey {
        ed25519: ed25519_secret.to_vec(),
        ml_dsa: ml_dsa_secret.into_bytes().to_vec(),
    };
    (sk, [0xA5u8; 32])
}

#[library_benchmark]
#[bench::bp_plus_2_outputs(setup = fresh_2out_commitments)]
fn crypto_bench_bulletproofs_plus_2_outputs(commitments: Vec<Commitment>) {
    let mut rng = seeded_rng();
    let bp = Bulletproof::prove_plus(&mut rng, black_box(commitments)).expect("bp prove");
    black_box(bp);
}

#[library_benchmark]
#[bench::hybrid_sign_1_input(setup = seeded_signing_state)]
fn crypto_bench_hybrid_sign_1_input(state: (HybridSecretKey, [u8; 32])) {
    let (sk, message) = state;

    // ── Ed25519 (deterministic by construction: RFC 8032 §5.1.6 derives
    //    the nonce from SHA-512 of the secret key + message, no RNG
    //    draw) ────────────────────────────────────────────────────────
    let ed25519_secret: [u8; ED25519_SECRET_KEY_LENGTH] = sk
        .ed25519
        .as_slice()
        .try_into()
        .expect("ed25519 secret length");
    let signing_key = SigningKey::from_bytes(&ed25519_secret);
    let ed25519_signature = signing_key.sign(&message);

    // ── ML-DSA-65 (deterministic variant; see top-of-file docstring
    //    for why we bypass `HybridEd25519MlDsa::sign` here) ──────────
    let ml_dsa_secret: [u8; ML_DSA_65_SECRET_KEY_LENGTH] = sk
        .ml_dsa
        .as_slice()
        .try_into()
        .expect("ml-dsa secret length");
    let ml_dsa_private =
        ml_dsa_65::PrivateKey::try_from_bytes(ml_dsa_secret).expect("ml-dsa sk decode");
    let ml_dsa_signature = ml_dsa_private
        .try_sign_with_seed(black_box(&BENCH_SEED), black_box(&message), &[])
        .expect("ml-dsa sign");

    let sig = HybridSignature {
        ed25519: ed25519_signature.to_bytes().to_vec(),
        ml_dsa: ml_dsa_signature.to_vec(),
    };
    black_box(sig);
}

library_benchmark_group!(
    name = transfer_e2e;
    benchmarks =
        crypto_bench_bulletproofs_plus_2_outputs,
        crypto_bench_hybrid_sign_1_input,
);

main!(library_benchmark_groups = transfer_e2e);
