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

/// Classification of a decrypted 8-byte label plaintext block (§5.7.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelPlaintextKind {
    Sentinel,
    Request(u64),
    Unknown([u8; 8]),
}

/// Classify decrypted label plaintext per §5.7.11.
#[must_use]
pub fn classify_label_plaintext(plaintext: &[u8; 8]) -> LabelPlaintextKind {
    if is_sentinel_plaintext(plaintext) {
        return LabelPlaintextKind::Sentinel;
    }
    if plaintext[0] == LABEL_WIRE_VERSION && plaintext[1] == LABEL_KIND_REQUEST {
        let mut rid_le = [0u8; 8];
        rid_le[..6].copy_from_slice(&plaintext[2..8]);
        let rid = u64::from_le_bytes(rid_le);
        if rid == 0 {
            return LabelPlaintextKind::Unknown(*plaintext);
        }
        return LabelPlaintextKind::Request(rid);
    }
    LabelPlaintextKind::Unknown(*plaintext)
}

/// Maximum `rid` encodable in bytes `[2..7]` (u48 LE). Keep in sync with
/// `shekyl_engine_state::PAYMENT_REQUEST_RID_U48_MAX`.
pub const REQUEST_RID_U48_MAX: u64 = (1u64 << 48) - 1;

/// Build the 8-byte REQUEST plaintext for cooperative send (§5.7.11).
///
/// Returns `None` if `rid` is `0`, exceeds u48, or the encoding would collide
/// with sentinel.
pub fn encode_request_plaintext(rid: u64) -> Option<[u8; 8]> {
    if rid == 0 || rid > REQUEST_RID_U48_MAX {
        return None;
    }
    let mut pt = [0u8; 8];
    pt[0] = LABEL_WIRE_VERSION;
    pt[1] = LABEL_KIND_REQUEST;
    let le = rid.to_le_bytes();
    pt[2..8].copy_from_slice(&le[..6]);
    if pt == SENTINEL_PLAINTEXT {
        return None;
    }
    Some(pt)
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

    #[test]
    fn request_plaintext_roundtrip() {
        let rid = 0x0000_1234_5678_9ABC_u64;
        let pt = encode_request_plaintext(rid).unwrap();
        assert_eq!(
            classify_label_plaintext(&pt),
            LabelPlaintextKind::Request(rid)
        );
        assert!(!is_sentinel_plaintext(&pt));
    }

    #[test]
    fn request_plaintext_rejects_rid_above_u48() {
        assert!(encode_request_plaintext(REQUEST_RID_U48_MAX).is_some());
        assert!(encode_request_plaintext(REQUEST_RID_U48_MAX + 1).is_none());
    }
}
