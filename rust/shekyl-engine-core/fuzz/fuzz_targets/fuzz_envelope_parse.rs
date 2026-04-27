#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use shekyl_engine_core::multisig::v31::messages::MultisigEnvelope;
    if let Ok(env) = MultisigEnvelope::from_bytes(data) {
        let bytes = env.to_bytes();
        let _ = MultisigEnvelope::from_bytes(&bytes);
    }
});
