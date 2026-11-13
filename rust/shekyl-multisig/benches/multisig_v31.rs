// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Performance benchmarks for V3.1 multisig protocol operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_intent_hash(c: &mut Criterion) {
    use shekyl_multisig::intent::{IntentRecipient, SpendIntent, SPEND_INTENT_VERSION};

    let intent = SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0x42; 32],
        address_fingerprint: [0xBB; 32],
        proposer_index: 0,
        signers: vec![0, 2],
        responder_index: 2,
        created_at: 1000000,
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
        address_fingerprint: [0xBB; 32],
        proposer_index: 0,
        signers: vec![0, 2],
        responder_index: 2,
        created_at: 1000000,
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
    bench_chain_state_fingerprint,
);
criterion_main!(benches);
