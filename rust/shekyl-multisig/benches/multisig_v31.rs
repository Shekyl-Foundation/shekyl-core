// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Performance benchmarks for V3.1 multisig protocol operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_intent_hash(c: &mut Criterion) {
    use shekyl_multisig::intent::{IntentRecipient, SpendIntent, SPEND_INTENT_VERSION};

    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x42; 32],
        group_id: [0xBB; 32],
        proposer_index: 0,
        proposer_sig: vec![0xAA; 64],
        created_at: 1000000,
        expires_at: 1086400,
        tx_counter: 1,
        reference_block_height: 999900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![IntentRecipient {
            address: vec![0x01; 4],
            amount: shekyl_units::AtomicUnits::from_raw(1_000_000_000),
        }],
        fee: shekyl_units::AtomicUnits::from_raw(1_000_000),
        input_global_indices: vec![12345],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0xEE; 32],
    };

    c.bench_function("intent_hash", |b| {
        b.iter(|| black_box(intent.intent_hash().unwrap()))
    });
}

fn bench_intent_serialization(c: &mut Criterion) {
    use shekyl_multisig::intent::{IntentRecipient, SpendIntent, SPEND_INTENT_VERSION};

    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x42; 32],
        group_id: [0xBB; 32],
        proposer_index: 0,
        proposer_sig: vec![0xAA; 64],
        created_at: 1000000,
        expires_at: 1086400,
        tx_counter: 1,
        reference_block_height: 999900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![IntentRecipient {
            address: vec![0x01; 4],
            amount: shekyl_units::AtomicUnits::from_raw(1_000_000_000),
        }],
        fee: shekyl_units::AtomicUnits::from_raw(1_000_000),
        input_global_indices: vec![12345],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0xEE; 32],
    };

    c.bench_function("intent_to_canonical_bytes", |b| {
        b.iter(|| black_box(intent.to_canonical_bytes().unwrap()))
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    use shekyl_multisig::encryption::{decrypt_payload, encrypt_payload};
    use shekyl_multisig::messages::MessageType;

    let key = [0x42; 32];
    let intent_hash = [0xAA; 32];
    let plaintext = vec![0xBB; 1024];

    let ct = encrypt_payload(
        &key,
        &intent_hash,
        MessageType::SpendIntent,
        0,
        1,
        &plaintext,
    )
    .unwrap();

    c.bench_function("encrypt_1kb", |b| {
        b.iter(|| {
            black_box(
                encrypt_payload(
                    &key,
                    &intent_hash,
                    MessageType::SpendIntent,
                    0,
                    1,
                    &plaintext,
                )
                .unwrap(),
            )
        })
    });

    c.bench_function("decrypt_1kb", |b| {
        b.iter(|| {
            black_box(
                decrypt_payload(&key, &intent_hash, MessageType::SpendIntent, 0, 1, &ct).unwrap(),
            )
        })
    });
}

fn bench_envelope_roundtrip(c: &mut Criterion) {
    use shekyl_multisig::messages::{MultisigEnvelope, ENVELOPE_VERSION};

    let envelope = MultisigEnvelope {
        version: ENVELOPE_VERSION,
        group_id: [0xAA; 32],
        intent_hash: [0xBB; 32],
        sender_index: 0,
        sender_sig: vec![0; 64],
        encrypted_payload: vec![0xCC; 512],
    };

    let bytes = envelope.to_bytes().unwrap();

    c.bench_function("envelope_serialize", |b| {
        b.iter(|| black_box(envelope.to_bytes().unwrap()))
    });

    c.bench_function("envelope_deserialize", |b| {
        b.iter(|| black_box(MultisigEnvelope::from_bytes(&bytes).unwrap()))
    });
}

fn bench_chain_state_fingerprint(c: &mut Criterion) {
    use shekyl_multisig::intent::ChainStateFingerprint;

    let fp = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: (0..16).collect(),
        input_eligible_heights: (900..916).collect(),
        input_amounts: vec![shekyl_units::AtomicUnits::from_raw(1_000_000); 16],
    };

    c.bench_function("chain_state_fingerprint_16_inputs", |b| {
        b.iter(|| black_box(fp.compute()))
    });
}

criterion_group!(
    benches,
    bench_intent_hash,
    bench_intent_serialization,
    bench_encrypt_decrypt,
    bench_envelope_roundtrip,
    bench_chain_state_fingerprint,
);
criterion_main!(benches);
