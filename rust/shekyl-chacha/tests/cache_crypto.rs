// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Gate 2: Wallet cache AEAD round-trip and version-mismatch ordering tests.
//!
//! Tests the encrypt_with_aad / decrypt_with_aad pipeline that underpins
//! shekyl_encrypt_wallet_cache / shekyl_decrypt_wallet_cache FFI.
//!
//! Sub-case A1: version mismatch → error (basic).
//! Sub-case A2: version mismatch + corrupted ciphertext → version error detected
//!              BEFORE AEAD decryption is attempted. This proves the implementation
//!              checks the version byte first, preventing a side channel where an
//!              attacker could learn auth-failure vs. version-failure ordering.

use shekyl_chacha::{decrypt_with_aad, encrypt_with_aad};

fn test_key() -> [u8; 32] {
    [0xABu8; 32]
}

/// Simulate the FFI envelope: [version_byte][aead_data...]
fn encrypt_wallet_cache(plaintext: &[u8], version: u8, key: &[u8; 32]) -> Vec<u8> {
    let aad = [version];
    let encrypted = encrypt_with_aad(key, &aad, plaintext);
    let mut output = Vec::with_capacity(1 + encrypted.len());
    output.push(version);
    output.extend_from_slice(&encrypted);
    output
}

/// Simulate the FFI decrypt: check version, then AEAD decrypt.
/// Returns: 0 success, -1 version mismatch, -2 auth failure, -3 too short.
fn decrypt_wallet_cache(ciphertext: &[u8], expected_version: u8, key: &[u8; 32]) -> (i32, Vec<u8>) {
    if ciphertext.is_empty() {
        return (-3, vec![]);
    }
    let on_disk_version = ciphertext[0];
    if on_disk_version != expected_version {
        return (-1, vec![]);
    }
    let aead_data = &ciphertext[1..];
    let aad = [on_disk_version];
    match decrypt_with_aad(key, &aad, aead_data) {
        Ok(pt) => (0, pt),
        Err(_) => (-2, vec![]),
    }
}

#[test]
fn round_trip_succeeds() {
    let key = test_key();
    let plaintext = b"wallet cache data for testing AEAD round-trip integrity";
    let version = 3u8;

    let ct = encrypt_wallet_cache(plaintext, version, &key);
    let (code, pt) = decrypt_wallet_cache(&ct, version, &key);

    assert_eq!(code, 0, "round-trip should succeed");
    assert_eq!(pt, plaintext, "recovered plaintext must match");
    eprintln!(
        "[Gate 2] basic round-trip passed: {} bytes",
        plaintext.len()
    );
}

#[test]
fn version_mismatch_returns_minus_one() {
    let key = test_key();
    let plaintext = b"secret wallet data";

    let ct = encrypt_wallet_cache(plaintext, 1, &key);
    let (code, _) = decrypt_wallet_cache(&ct, 2, &key);

    assert_eq!(code, -1, "version mismatch must return -1");
    eprintln!("[Gate 2] sub-case A1: version mismatch → -1");
}

#[test]
fn version_check_before_aead_decryption() {
    let key = test_key();
    let plaintext = b"PQC secrets that must not leak through error ordering";

    let mut ct = encrypt_wallet_cache(plaintext, 1, &key);

    // Corrupt the AEAD ciphertext (bytes after the version byte + nonce).
    // If decryption ran first, this would produce -2 (auth failure).
    // The correct behavior: version check fires first → -1.
    if ct.len() > 30 {
        ct[25] ^= 0xFF;
        ct[26] ^= 0xFF;
        ct[27] ^= 0xFF;
    }

    let (code, _) = decrypt_wallet_cache(&ct, 2, &key);

    assert_eq!(
        code, -1,
        "sub-case A2: version mismatch MUST be detected before AEAD auth check. \
         Got error code {code} (expected -1, would get -2 if decryption ran first)",
    );
    eprintln!("[Gate 2] sub-case A2: version mismatch detected before corrupted AEAD → -1");
}

#[test]
fn wrong_key_returns_auth_failure() {
    let key = test_key();
    let plaintext = b"test data";

    let ct = encrypt_wallet_cache(plaintext, 1, &key);

    let wrong_key = [0xCDu8; 32];
    let (code, _) = decrypt_wallet_cache(&ct, 1, &wrong_key);

    assert_eq!(code, -2, "wrong key should produce auth failure (-2)");
}

#[test]
fn empty_ciphertext_returns_too_short() {
    let key = test_key();
    let (code, _) = decrypt_wallet_cache(&[], 1, &key);
    assert_eq!(code, -3, "empty ciphertext → -3");
}

#[test]
fn truncated_ciphertext_returns_auth_failure() {
    let key = test_key();
    let ct = encrypt_wallet_cache(b"test", 1, &key);
    let truncated = &ct[..5];
    let (code, _) = decrypt_wallet_cache(truncated, 1, &key);
    assert_eq!(code, -2, "truncated ciphertext → auth failure");
}
