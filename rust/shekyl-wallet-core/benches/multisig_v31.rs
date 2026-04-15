// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Performance benchmarks for V3.1 multisig protocol operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_intent_hash(c: &mut Criterion) {
    use shekyl_wallet_core::multisig::v31::intent::{
        IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
    };

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
            amount: 1_000_000_000,
        }],
        fee: 1_000_000,
        input_global_indices: vec![12345],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0xEE; 32],
    };

    c.bench_function("intent_hash", |b| {
        b.iter(|| black_box(intent.intent_hash()))
    });
}

fn bench_intent_serialization(c: &mut Criterion) {
    use shekyl_wallet_core::multisig::v31::intent::{
        IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
    };

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
            amount: 1_000_000_000,
        }],
        fee: 1_000_000,
        input_global_indices: vec![12345],
        kem_randomness_seed: [0xDD; 32],
        chain_state_fingerprint: [0xEE; 32],
    };

    c.bench_function("intent_to_canonical_bytes", |b| {
        b.iter(|| black_box(intent.to_canonical_bytes()))
    });
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    use shekyl_wallet_core::multisig::v31::encryption::{decrypt_payload, encrypt_payload};
    use shekyl_wallet_core::multisig::v31::messages::MessageType;

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
    use shekyl_wallet_core::multisig::v31::messages::{MultisigEnvelope, ENVELOPE_VERSION};

    let envelope = MultisigEnvelope {
        version: ENVELOPE_VERSION,
        group_id: [0xAA; 32],
        intent_hash: [0xBB; 32],
        sender_index: 0,
        sender_sig: vec![0; 64],
        encrypted_payload: vec![0xCC; 512],
    };

    let bytes = envelope.to_bytes();

    c.bench_function("envelope_serialize", |b| {
        b.iter(|| black_box(envelope.to_bytes()))
    });

    c.bench_function("envelope_deserialize", |b| {
        b.iter(|| black_box(MultisigEnvelope::from_bytes(&bytes).unwrap()))
    });
}

fn bench_chain_state_fingerprint(c: &mut Criterion) {
    use shekyl_wallet_core::multisig::v31::intent::ChainStateFingerprint;

    let fp = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: (0..16).collect(),
        input_eligible_heights: (900..916).collect(),
        input_amounts: vec![1_000_000; 16],
        input_assigned_prover_indices: (0..16).map(|i| (i % 3) as u8).collect(),
    };

    c.bench_function("chain_state_fingerprint_16_inputs", |b| {
        b.iter(|| black_box(fp.compute()))
    });
}

fn bench_assembly_consensus(c: &mut Criterion) {
    use shekyl_wallet_core::multisig::v31::invariants::check_assembly_consensus;
    use shekyl_wallet_core::multisig::v31::prover::SignatureShare;

    let shares: Vec<_> = (0..7)
        .map(|i| SignatureShare {
            signer_index: i,
            hybrid_sig: vec![0; 64],
            tx_hash_commitment: [0xAA; 32],
            fcmp_proof_commitment: [0xBB; 32],
            bp_plus_proof_commitment: [0xCC; 32],
        })
        .collect();

    c.bench_function("assembly_consensus_7_signers", |b| {
        b.iter(|| black_box(check_assembly_consensus(&shares)))
    });
}

criterion_group!(
    benches,
    bench_intent_hash,
    bench_intent_serialization,
    bench_encrypt_decrypt,
    bench_envelope_roundtrip,
    bench_chain_state_fingerprint,
    bench_assembly_consensus,
);
criterion_main!(benches);
