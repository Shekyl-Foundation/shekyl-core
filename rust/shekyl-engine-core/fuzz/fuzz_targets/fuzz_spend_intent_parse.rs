#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 200 || data.len() > 4096 {
        return;
    }
    use shekyl_engine_core::multisig::v31::intent::SpendIntent;
    if let Ok(intent) = SpendIntent::from_canonical_bytes(data) {
        let _ = intent.intent_hash();
        let _ = intent.to_canonical_bytes();
        let _ = intent.validate_structural(3, 1000);
    }
});
