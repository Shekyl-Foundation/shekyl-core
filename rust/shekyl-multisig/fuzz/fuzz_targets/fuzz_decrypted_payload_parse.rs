#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use shekyl_multisig::messages::DecryptedPayload;
    if let Ok(dp) = DecryptedPayload::decode(data) {
        let encoded = dp.encode();
        let _ = DecryptedPayload::decode(&encoded);
    }
});
