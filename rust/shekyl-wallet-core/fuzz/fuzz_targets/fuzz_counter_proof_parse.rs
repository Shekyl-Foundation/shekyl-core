#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use shekyl_wallet_core::multisig::v31::counter_proof::CounterProof;
    if let Ok(cp) = serde_json::from_slice::<CounterProof>(data) {
        let bytes = cp.signable_bytes();
        assert!(!bytes.is_empty());
    }
});
