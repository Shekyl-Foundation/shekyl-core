#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 100 {
        return;
    }
    use shekyl_multisig::intent::{IntentRecipient, SpendIntent};
    use shekyl_units::AtomicUnits;

    let intent = SpendIntent {
        version: data[0],
        intent_id: data[1..33].try_into().unwrap_or([0; 32]),
        address_fingerprint: data[33..65].try_into().unwrap_or([0; 32]),
        proposer_index: data[65],
        signers: data[66..usize::from(data[96] % 6) + 66].to_vec(),
        responder_index: data[97],
        created_at: u64::from_le_bytes(data[74..82].try_into().unwrap_or([0; 8])),
        tx_counter: u64::from_le_bytes(data[82..90].try_into().unwrap_or([0; 8])),
        reference_block_height: u64::from_le_bytes(data[88..96].try_into().unwrap_or([0; 8])),
        reference_block_hash: [0; 32],
        recipients: vec![IntentRecipient {
            address: vec![1],
            amount: AtomicUnits::from_raw(100),
        }],
        fee: AtomicUnits::from_raw(10),
        input_global_indices: vec![42],
        kem_randomness_seed: [0; 32],
        chain_state_fingerprint: [0; 32],
    };

    let _ = intent.validate_structural(data[98] % 7, data[99] % 7);
    let _ = intent.validate_temporal(
        0,
        u64::from_le_bytes(data[90..98].try_into().unwrap_or([0; 8])),
        &[0; 32],
    );
    let _ = intent.intent_hash();
    let _ = intent.to_canonical_bytes();
});
