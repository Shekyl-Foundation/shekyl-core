// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hardening-pass commit 2 (§3.2): 1-in / 2-out transfer crypto components.
//!
//! **Scope note (manifest-discipline).** A full `sign_transaction`
//! requires a valid FCMP++ curve-tree path fixture keyed to the
//! daemon's current tree root. Shipping a checked-in fixture is its
//! own scope of work (tracked as a known gap in
//! `docs/benchmarks/shekyl_rust_v0.manifest.md` §4). In the interim,
//! this bench composes the two crypto pieces of a 1-in/2-out transfer
//! that we *can* exercise hermetically:
//!
//! 1. Bulletproofs+ range proof over 2 Pedersen commitments (the two
//!    output commitments of a standard "spend to recipient +
//!    change-back" transfer).
//! 2. One hybrid Ed25519 + ML-DSA-65 signature (the PQC auth attached
//!    to the single input).
//!
//! Together these account for ~all of the wall-clock cost of a real
//! `sign_transaction` except the FCMP++ membership proof. The
//! manifest is explicit that a delta here is interpretable as a
//! regression in BP+ or ML-DSA-65 only; membership-proof cost is
//! tracked separately once the tree fixture lands.
//!
//! Naming convention: `crypto_bench_*` — bidirectional threshold.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};

use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSecretKey, SignatureScheme};
use shekyl_primitives::Commitment;

/// Build the two Pedersen commitments for a standard 1-in/2-out
/// transfer (recipient + change). Deterministic-ish: amounts
/// generated via `OsRng::next_u64()` so the bench input is distinct
/// per iteration, mirroring real sign-path behavior where no two
/// transfers share a blinding factor.
fn fresh_2out_commitments() -> Vec<Commitment> {
    let recipient = Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64());
    let change = Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64());
    vec![recipient, change]
}

/// Pre-generate an Ed25519 + ML-DSA-65 hybrid secret key. Done once
/// outside the measured region because keygen is not on the
/// per-transfer hot path; the transfer cost we care about is the
/// sign step that happens every time a user spends.
fn fresh_hybrid_secret_key() -> HybridSecretKey {
    let scheme = HybridEd25519MlDsa;
    let (_pk, sk) = scheme
        .keypair_generate()
        .expect("hybrid keypair generation");
    sk
}

fn crypto_bench_transfer_e2e_components(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bench_transfer_e2e_1in_2out");

    // ── BP+ range proof (2 outputs) ──
    group.bench_function("bulletproofs_plus_2_outputs", |b| {
        b.iter_batched(
            fresh_2out_commitments,
            |commitments| {
                let bp =
                    Bulletproof::prove_plus(&mut OsRng, black_box(commitments)).expect("bp prove");
                black_box(bp);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // ── Hybrid Ed25519 + ML-DSA-65 sign (1 input's PQC auth) ──
    let sk = fresh_hybrid_secret_key();
    let scheme = HybridEd25519MlDsa;
    // The actual message-under-sign for a transaction is the 32-byte
    // sighash of the tx; using a fixed-length random-ish buffer keeps
    // the ML-DSA-65 input shape realistic without tying the bench to
    // the tx-sighash construction.
    let message = [0xA5u8; 32];
    group.bench_function("hybrid_sign_1_input", |b| {
        b.iter(|| {
            let sig = scheme
                .sign(black_box(&sk), black_box(&message))
                .expect("hybrid sign");
            black_box(sig);
        });
    });

    group.finish();
}

criterion_group!(benches, crypto_bench_transfer_e2e_components);
criterion_main!(benches);
