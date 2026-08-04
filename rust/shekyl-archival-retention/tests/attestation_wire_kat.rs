// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-pinned KAT for the credit-wire record format (`ARCHIVAL_CREDIT_WIRE.md`
//! §3): `AttestationHeader::to_canonical_bytes`, `attestation_nonce`, and
//! `attestation_root`.
//!
//! These pins are the tripwire the crate's other attestation tests cannot be:
//! every unit test in `attestation_wire.rs` is self-consistent (compute twice,
//! or sign-then-verify), so a changed customization string, a reordered field,
//! or an LE↔BE flip would flip *nothing* red. Here the exact output bytes are
//! frozen, so any such change fails loudly — and these are the same vectors
//! Plan B's C++ block-format code differential-tests against when the cutover's
//! equivalence-KAT (§5 step 2) runs.
//!
//! To regenerate after a *deliberate* format change:
//! `cargo test -p shekyl-archival-retention --test attestation_wire_kat \
//!   regenerate_attestation_wire_vectors -- --ignored --nocapture`
//! then paste the printed hexes into the constants below.

use shekyl_archival_retention::{
    attestation_nonce, attestation_root, AttestationHeader, AttestationKind, PassRecord,
};
use shekyl_crypto_pq::signature::{
    HybridSignature, HYBRID_SCHEME_ID_ED25519_ML_DSA_65, HYBRID_SIG_VERSION,
    ML_DSA_65_SIGNATURE_LENGTH,
};

// ---- Header vector (hand-verifiable: p_id ‖ shard_le ‖ epoch_le ‖ kind) ----
const HDR_P_ID: [u8; 32] = [0x11; 32];
const HDR_SHARD_ID: u64 = 0x1122_3344_5566_7788;
const HDR_EPOCH: u64 = 0x99AA_BBCC_DDEE_FF00;
/// `[0x11;32]` ‖ shard little-endian (`8877665544332211`) ‖ epoch little-endian
/// (`00ffeeddccbbaa99`) ‖ kind byte (`01` = pass). Hand-computed, so the LE
/// field order is pinned independently of the implementation.
const HDR_EXPECT_HEX: &str = concat!(
    "1111111111111111111111111111111111111111111111111111111111111111",
    "8877665544332211",
    "00ffeeddccbbaa99",
    "01",
);

// ---- Nonce vector: attestation_nonce(r, cb, p_id, shard, epoch) ----
const NONCE_R: [u8; 32] = [0x01; 32];
const NONCE_CB: [u8; 32] = [0x02; 32];
const NONCE_P_ID: [u8; 32] = [0x03; 32];
const NONCE_SHARD: u64 = 5;
const NONCE_EPOCH: u64 = 7;
const NONCE_EXPECT_HEX: &str = "796544f6e98a4f7d209551a7411c09a3dbf0fb9119b5cf826da7b0010f362ea2";

// ---- Root vectors ----
/// Deterministic fill bytes for two dummy pass-signatures (the root serializes
/// canonical bytes only; it never verifies, so fixed fills suffice and keep the
/// vector reproducible where a real ML-DSA signature is randomized).
const SIG_A_ED_FILL: u8 = 0xA1;
const SIG_A_ML_FILL: u8 = 0xA2;
const SIG_B_ED_FILL: u8 = 0xB1;
const SIG_B_ML_FILL: u8 = 0xB2;
const ROOT_EMPTY_EXPECT_HEX: &str =
    "32b1bcd9532f6f0cad787eeeb126c307cdd6c9712b914fd6ba087d6a36bb7bf2";
const ROOT_TWO_EXPECT_HEX: &str =
    "d0a627303a97197f56db53d1251a9b616f4f834e0ae99871a772ed7e693ea6b1";

fn header(p_id: [u8; 32], shard_id: u64, settlement_epoch: u64) -> AttestationHeader {
    AttestationHeader {
        p_id,
        shard_id,
        settlement_epoch,
        kind: AttestationKind::Pass,
    }
}

/// Ed25519 signature length implied by the public hybrid framing
/// (`HybridSignature::CANONICAL_LEN` − framing − ML-DSA-65 sig).
const ED25519_SIG_LEN: usize =
    HybridSignature::CANONICAL_LEN - 1 - 1 - 2 - 4 - 4 - ML_DSA_65_SIGNATURE_LENGTH;

/// Two dummy same-length canonical signatures from fixed fills — **no RNG**.
/// Lengths come from the scheme framing constants, not from a live keygen.
fn dummy_sig_pair() -> (HybridSignature, HybridSignature) {
    (
        HybridSignature {
            ed25519: vec![SIG_A_ED_FILL; ED25519_SIG_LEN],
            ml_dsa: vec![SIG_A_ML_FILL; ML_DSA_65_SIGNATURE_LENGTH],
        },
        HybridSignature {
            ed25519: vec![SIG_B_ED_FILL; ED25519_SIG_LEN],
            ml_dsa: vec![SIG_B_ML_FILL; ML_DSA_65_SIGNATURE_LENGTH],
        },
    )
}

/// Sanity: dummy fills round-trip through canonical framing (lengths valid).
#[test]
fn dummy_sigs_are_canonical_length() {
    let (sa, sb) = dummy_sig_pair();
    assert_eq!(
        sa.to_canonical_bytes().unwrap().len(),
        HybridSignature::CANONICAL_LEN
    );
    assert_eq!(
        sb.to_canonical_bytes().unwrap().len(),
        HybridSignature::CANONICAL_LEN
    );
    // Framing constants used above match what to_canonical_bytes emits.
    let bytes = sa.to_canonical_bytes().unwrap();
    assert_eq!(bytes[0], HYBRID_SIG_VERSION);
    assert_eq!(bytes[1], HYBRID_SCHEME_ID_ED25519_ML_DSA_65);
}

/// The two-record root vector: header A + dummy A, header B + dummy B.
fn two_record_root() -> [u8; 32] {
    let (sa, sb) = dummy_sig_pair();
    attestation_root(&[
        PassRecord {
            p_id: HDR_P_ID,
            shard_id: 1,
            settlement_epoch: 100,
            signature: sa,
        },
        PassRecord {
            p_id: [0x22; 32],
            shard_id: 2,
            settlement_epoch: 200,
            signature: sb,
        },
    ])
    .expect("root over canonical-length dummies")
}

#[test]
fn header_canonical_bytes_match_pin() {
    let bytes = header(HDR_P_ID, HDR_SHARD_ID, HDR_EPOCH).to_canonical_bytes();
    assert_eq!(hex::encode(bytes), HDR_EXPECT_HEX);
}

#[test]
fn nonce_matches_pin() {
    let nonce = attestation_nonce(&NONCE_R, &NONCE_CB, &NONCE_P_ID, NONCE_SHARD, NONCE_EPOCH);
    assert_eq!(hex::encode(nonce), NONCE_EXPECT_HEX);
}

#[test]
fn empty_root_matches_pin() {
    assert_eq!(
        hex::encode(attestation_root(&[]).unwrap()),
        ROOT_EMPTY_EXPECT_HEX
    );
}

#[test]
fn two_record_root_matches_pin() {
    assert_eq!(hex::encode(two_record_root()), ROOT_TWO_EXPECT_HEX);
}

#[test]
#[ignore = "prints the current wire hexes; run with --nocapture to regenerate the pins"]
fn regenerate_attestation_wire_vectors() {
    let hdr = header(HDR_P_ID, HDR_SHARD_ID, HDR_EPOCH).to_canonical_bytes();
    let nonce = attestation_nonce(&NONCE_R, &NONCE_CB, &NONCE_P_ID, NONCE_SHARD, NONCE_EPOCH);
    println!("HDR_EXPECT_HEX        = \"{}\"", hex::encode(hdr));
    println!("NONCE_EXPECT_HEX      = \"{}\"", hex::encode(nonce));
    println!(
        "ROOT_EMPTY_EXPECT_HEX = \"{}\"",
        hex::encode(attestation_root(&[]).unwrap())
    );
    println!(
        "ROOT_TWO_EXPECT_HEX   = \"{}\"",
        hex::encode(two_record_root())
    );
}
