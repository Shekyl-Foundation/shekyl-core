#![no_main]
//! A spend intent from untrusted bytes: the canonical decoder, then every
//! check a member runs that needs no chain view of its own.
use libfuzzer_sys::fuzz_target;
use shekyl_address::Network;
use shekyl_multisig::intent::SpendIntent;

/// The group shape the checks run against: the largest, so every signer
/// and recipient bound is reachable.
const N_TOTAL: u8 = 5;
const M_REQUIRED: u8 = 3;

fuzz_target!(|data: &[u8]| {
    let Ok(intent) = SpendIntent::from_canonical_bytes(data) else {
        return;
    };
    // The decoder is exact: the bytes it accepts are the intent's encoding.
    assert_eq!(intent.to_canonical_bytes().unwrap(), data);
    let _ = intent.validate_structural(N_TOTAL, M_REQUIRED);
    let _ = intent.resolve_recipients(Network::Testnet);
    let _ = intent.validate_temporal(intent.reference_block_height, &intent.reference_block_hash);
    let _ = intent.intent_hash();
});
