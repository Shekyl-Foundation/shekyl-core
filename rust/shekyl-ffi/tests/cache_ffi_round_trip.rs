use shekyl_ffi::{
    shekyl_buffer_free, shekyl_decrypt_wallet_cache, shekyl_encrypt_wallet_cache, ShekylBuffer,
};

fn make_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = 0xAA;
    key[15] = 0xBB;
    key[31] = 0xCC;
    key
}

fn encrypt(plaintext: &[u8], version: u8, key: &[u8; 32]) -> Vec<u8> {
    let mut out = ShekylBuffer { ptr: std::ptr::null_mut(), len: 0 };
    let ok = unsafe {
        shekyl_encrypt_wallet_cache(
            plaintext.as_ptr(),
            plaintext.len(),
            version,
            key.as_ptr(),
            &mut out,
        )
    };
    assert!(ok, "shekyl_encrypt_wallet_cache returned false");
    assert!(!out.ptr.is_null());
    let ct = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { shekyl_buffer_free(out.ptr, out.len) };
    ct
}

fn decrypt(ciphertext: &[u8], expected_version: u8, key: &[u8; 32]) -> (i32, Vec<u8>) {
    let mut out = ShekylBuffer { ptr: std::ptr::null_mut(), len: 0 };
    let rc = unsafe {
        shekyl_decrypt_wallet_cache(
            ciphertext.as_ptr(),
            ciphertext.len(),
            expected_version,
            key.as_ptr(),
            &mut out,
        )
    };
    if rc == 0 {
        assert!(!out.ptr.is_null());
        let pt = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
        unsafe { shekyl_buffer_free(out.ptr, out.len) };
        (0, pt)
    } else {
        (rc, Vec::new())
    }
}

#[test]
fn round_trip_normal() {
    let key = make_key();
    let plaintext = b"Hello, Shekyl wallet cache!";
    let ct = encrypt(plaintext, 1, &key);
    let (rc, pt) = decrypt(&ct, 1, &key);
    assert_eq!(rc, 0, "decrypt returned error code {rc}");
    assert_eq!(pt, plaintext, "decrypted plaintext does not match original");
}

#[test]
fn version_mismatch_detected_before_aead() {
    let key = make_key();
    let ct = encrypt(b"secret data", 1, &key);
    let (rc, _) = decrypt(&ct, 2, &key);
    assert_eq!(rc, -1, "expected version mismatch error (-1), got {rc}");
}

#[test]
fn flipped_version_byte_detected_as_auth_failure() {
    let key = make_key();
    let mut ct = encrypt(b"secret data", 1, &key);
    ct[0] ^= 0xFF;
    let (rc, _) = decrypt(&ct, ct[0], &key);
    assert_eq!(rc, -2, "expected auth failure (-2) from flipped version byte, got {rc}");
}

#[test]
fn flipped_ciphertext_body_detected_as_auth_failure() {
    let key = make_key();
    let mut ct = encrypt(b"secret data", 1, &key);
    assert!(ct.len() > 10, "ciphertext unexpectedly short");
    ct[ct.len() / 2] ^= 0x01;
    let (rc, _) = decrypt(&ct, 1, &key);
    assert_eq!(rc, -2, "expected auth failure (-2) from flipped body byte, got {rc}");
}

#[test]
fn empty_ciphertext_returns_format_error() {
    let key = make_key();
    let (rc, _) = decrypt(&[], 1, &key);
    assert_eq!(rc, -3, "expected format error (-3) for empty input, got {rc}");
}

#[test]
fn wrong_key_returns_auth_failure() {
    let key = make_key();
    let ct = encrypt(b"secret data", 1, &key);
    let mut wrong_key = key;
    wrong_key[0] ^= 0x01;
    let (rc, _) = decrypt(&ct, 1, &wrong_key);
    assert_eq!(rc, -2, "expected auth failure (-2) for wrong key, got {rc}");
}

#[test]
fn large_plaintext_round_trip() {
    let key = make_key();
    let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let ct = encrypt(&plaintext, 1, &key);
    let (rc, pt) = decrypt(&ct, 1, &key);
    assert_eq!(rc, 0);
    assert_eq!(pt, plaintext);
}
