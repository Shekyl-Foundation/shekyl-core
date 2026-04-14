#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 65 {
        return;
    }
    use shekyl_wallet_core::multisig::v31::encryption::{decrypt_payload, encrypt_payload};
    use shekyl_wallet_core::multisig::v31::messages::MessageType;

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let intent_hash: [u8; 32] = data[32..64].try_into().unwrap();
    let sender = data[64];
    let plaintext = &data[65..];

    if let Ok(ct) = encrypt_payload(
        &key,
        &intent_hash,
        MessageType::SpendIntent,
        sender,
        0,
        plaintext,
    ) {
        let pt = decrypt_payload(
            &key,
            &intent_hash,
            MessageType::SpendIntent,
            sender,
            0,
            &ct,
        );
        assert_eq!(pt.unwrap(), plaintext);
    }
});
