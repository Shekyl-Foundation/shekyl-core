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
//!
//! Two arms are of the held key, [`FnDsaHybridSigner`] (`FND-4`):
//! `fn_dsa_hybrid_sign_held` is the production entry with the key decoded
//! before the loop, and `fn_dsa_hybrid_hold_key` is the one decode into a
//! held key; the wipe and release that end the key's life are dropped
//! outside the timed region.
//!
//! `fn_dsa_hybrid_persona_slot_derivation` is one persona slot's whole key
//! derivation, and `fn_dsa_hybrid_persona_receipt_keygen` the receipt key's
//! generation inside it, from that slot's own seeds (`FND-12`).

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{
    derive_archival_p_keys, derive_p_receipt_ed_seed, derive_p_receipt_fn_dsa_seed,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSecretKey, FnDsaHybridSignature, FnDsaHybridSigner,
    HybridEd25519FnDsa,
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

fn bench_sign_held(c: &mut Criterion) {
    let (_public, secret) = keypair();
    let mut signer = FnDsaHybridSigner::new(&secret).expect("the generated key decodes");
    c.bench_function("fn_dsa_hybrid_sign_held", |b| {
        b.iter(|| {
            signer
                .sign(SCHEME_DOMAIN_RECEIPT, black_box(&MESSAGE))
                .expect("sign")
        })
    });
}

fn bench_hold_key(c: &mut Criterion) {
    let (_public, secret) = keypair();
    // `iter_with_large_drop` drops each signer outside the timed region, so
    // the figure is the decode into a held key and not also the wipe and
    // the release of the ~114 kB context that ends its life.
    c.bench_function("fn_dsa_hybrid_hold_key", |b| {
        b.iter_with_large_drop(|| {
            FnDsaHybridSigner::new(black_box(&secret)).expect("the generated key decodes")
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

/// The persona whose slot the next two arms derive: mainnet, BIP-39, slot 0.
const PERSONA_MASTER: [u8; MASTER_SEED_BYTES] = [0x33; MASTER_SEED_BYTES];
const PERSONA_NETWORK: DerivationNetwork = DerivationNetwork::Mainnet;
const PERSONA_FORMAT: SeedFormat = SeedFormat::Bip39;
const PERSONA_SLOT: u32 = 0;

/// One persona slot's whole key derivation, the unit engine assembly pays
/// per held slot (`FND-12`, `FND-25`). Inside it: the HKDF expands; the
/// Ed25519 spend and view scalar multiplications and the X25519 conversion;
/// the ML-KEM-768 key generation; the SLH-DSA-192s message-signing key
/// generation; two Ed25519 + ML-DSA-65 key generations (identity and bond
/// spend); and the receipt key's Ed25519 + FN-DSA-1024 key generation.
fn bench_persona_slot(c: &mut Criterion) {
    c.bench_function("fn_dsa_hybrid_persona_slot_derivation", |b| {
        b.iter(|| {
            derive_archival_p_keys(
                black_box(&PERSONA_MASTER),
                PERSONA_NETWORK,
                PERSONA_FORMAT,
                black_box(PERSONA_SLOT),
            )
            .expect("persona derivation")
        })
    });
}

/// The receipt key's generation inside that same slot: the scheme's seeded
/// key generation from the two seeds `derive_archival_p_keys` derives for
/// this persona. FN-DSA key generation draws candidates until one is
/// usable, so its time depends on the seed; the share of a slot is read
/// from this arm and the persona arm, which are the same inputs, and not
/// from `fn_dsa_hybrid_keygen_from_seeds`, which is not.
fn bench_persona_receipt_keygen(c: &mut Criterion) {
    let ed25519 = derive_p_receipt_ed_seed(
        &PERSONA_MASTER,
        PERSONA_NETWORK,
        PERSONA_FORMAT,
        PERSONA_SLOT,
    );
    let fn_dsa = derive_p_receipt_fn_dsa_seed(
        &PERSONA_MASTER,
        PERSONA_NETWORK,
        PERSONA_FORMAT,
        PERSONA_SLOT,
    );
    c.bench_function("fn_dsa_hybrid_persona_receipt_keygen", |b| {
        b.iter(|| {
            HybridEd25519FnDsa::keypair_from_seeds(black_box(&ed25519), black_box(&fn_dsa))
                .expect("seeded keygen")
        })
    });
}

criterion_group!(
    benches,
    bench_sign,
    bench_sign_held,
    bench_hold_key,
    bench_verify,
    bench_keygen,
    bench_persona_slot,
    bench_persona_receipt_keygen
);
criterion_main!(benches);
