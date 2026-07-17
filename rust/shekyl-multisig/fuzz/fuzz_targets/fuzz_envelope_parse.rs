#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use shekyl_multisig::messages::MultisigEnvelope;
    if let Ok(env) = MultisigEnvelope::from_bytes(data) {
        if let Ok(bytes) = env.to_bytes() {
            let _ = MultisigEnvelope::from_bytes(&bytes);
        }
    }
});
