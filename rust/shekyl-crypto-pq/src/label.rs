// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output logical label encryption (5-T substrate, §5.7.11).
//!
//! Every output carries a fixed 8-byte **plaintext** XOR-encrypted under
//! per-output `k_label`, with a 1-byte `label_tag` integrity check — same
//! discipline as amounts.
//!
//! **Normative:** `SENTINEL_PLAINTEXT` (`0xFF…`) is the plaintext when no
//! cooperative tag is sent. On-wire `enc_label` bytes are `plaintext XOR
//! k_label[..8]` and **differ per output** even for sentinel sends. There is
//! **no** cleartext-constant wire path (writing `0xFF` directly into `enc_label`
//! is forbidden). `label_tag` is HKDF-derived like `amount_tag`; it is **not**
//! a sentinel-vs-tag category flag — classification happens only after decrypt.

use zeroize::Zeroizing;

/// Normative sentinel plaintext: no cooperative label (launch default).
pub const SENTINEL_PLAINTEXT: [u8; 8] = [0xFF; 8];

/// Wire version for meaningful (non-sentinel) tags.
pub const LABEL_WIRE_VERSION: u8 = 0x01;

/// `label_kind` for payment-request echo (`rid` in bytes [2..7]).
pub const LABEL_KIND_REQUEST: u8 = 0x01;

/// Return the 8-byte sentinel plaintext block (always encrypted on wire).
#[must_use]
pub fn sentinel_plaintext() -> [u8; 8] {
    SENTINEL_PLAINTEXT
}

/// XOR-encrypt an 8-byte label plaintext with `k_label[..8]`.
#[must_use]
pub fn encrypt_label_plaintext(plaintext: &[u8; 8], k_label: &[u8; 32]) -> [u8; 8] {
    let pt = Zeroizing::new(*plaintext);
    let mut enc = [0u8; 8];
    for i in 0..8 {
        enc[i] = pt[i] ^ k_label[i];
    }
    enc
}

/// XOR-decrypt an on-chain `enc_label` with `k_label[..8]`.
#[must_use]
pub fn decrypt_label_plaintext(enc_label: &[u8; 8], k_label: &[u8; 32]) -> [u8; 8] {
    let mut pt = [0u8; 8];
    for i in 0..8 {
        pt[i] = enc_label[i] ^ k_label[i];
    }
    pt
}

/// True if decrypted plaintext is the sentinel (no cooperative label).
#[must_use]
pub fn is_sentinel_plaintext(plaintext: &[u8; 8]) -> bool {
    *plaintext == SENTINEL_PLAINTEXT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_round_trip() {
        let k = [0x42u8; 32];
        let enc = encrypt_label_plaintext(&SENTINEL_PLAINTEXT, &k);
        let pt = decrypt_label_plaintext(&enc, &k);
        assert!(is_sentinel_plaintext(&pt));
    }
}
