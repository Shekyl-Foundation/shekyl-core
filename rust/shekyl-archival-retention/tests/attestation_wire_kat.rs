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
    attestation_nonce, attestation_root, AttestationHeader, AttestationKind,
    BlockAttestationWitness, PassRecord, WitnessError, ATTESTATION_HEADER_LEN,
    MAX_ATTESTATION_RECORDS, MAX_ATTESTATION_WITNESS_BYTES, WITNESS_PREFIX_LEN,
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
// Moved by the HYBRID_SIG_VERSION 1->2 bump (SA-R-4): the root commits
// header ‖ signature_canonical pairs, and each dummy signature's canonical
// encoding now begins with version byte 2. A version bump is a deliberate
// consensus edit, so it must move this tripwire.
const ROOT_TWO_EXPECT_HEX: &str =
    "90a3f26977797359782c99c284511d4f284225887a2b6a07383494ed690a65c0";

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

// Genesis-frozen consensus values, pinned as literals (a change is a deliberate
// consensus edit, so it must move this tripwire). These are the Rust authority the
// FFI exposes and C++ `config::` asserts equality/bound against (the credit-wire CW-1b-iv gate).
#[test]
fn attestation_constants_are_pinned() {
    assert_eq!(MAX_ATTESTATION_RECORDS, 256);
    assert_eq!(ATTESTATION_HEADER_LEN, 49);
    // Exact witness maximum = WITNESS_PREFIX_LEN + 256 × HybridSignature::CANONICAL_LEN.
    // Pinned to the literal so a signature-size change surfaces here rather than
    // silently in the coarse C++ cap.
    // RF-D3 (2026-08-19): the 32-byte `r` prefix is gone, so the framing is the
    // count alone and the maximum drops by exactly 32.
    assert_eq!(WITNESS_PREFIX_LEN, 8);
    assert_eq!(MAX_ATTESTATION_WITNESS_BYTES, 866_568);
}

// ---- Witness (count ‖ pass signatures) canonical-encoding vectors ----
//
// The block-hash differential is structurally blind to the witness (it rides no
// hashed field), so this is the freeze for the transport encoding. `count` is
// DERIVED on encode (pass_signatures.len()) and VALIDATED on decode
// (LengthMismatch) — there is no redundant stored count field, so no bad state to
// represent; a maintainer must not add one. The deterministic dummy_sig_pair
// makes every byte a pinned function of the operands, so the structural asserts
// below ARE the byte pin (and name which field drifted), with no lockstep
// encoder/regenerator hazard.
//
// The fixed `r` that used to seed this alongside the signatures is gone with the
// field itself (RF-D3): the nonce anchors to the validated predecessor hash,
// which the verifier holds as chain state and the witness never transports.

fn witness_two_sig() -> BlockAttestationWitness {
    let (sa, sb) = dummy_sig_pair();
    BlockAttestationWitness {
        pass_signatures: vec![sa, sb],
    }
}

#[test]
fn witness_canonical_encoding_is_pinned_by_structure() {
    let bytes = witness_two_sig().to_canonical_bytes().unwrap();
    let sig_len = HybridSignature::CANONICAL_LEN;
    let (sa, sb) = dummy_sig_pair();

    // Structure asserted against the operands directly (not via to_canonical_bytes),
    // so an encoder bug — big-endian count, wrong sig order — fails here.
    //
    // The 32-byte `r` prefix this used to pin is GONE (RF-D3, 2026-08-19): the
    // nonce anchors to the validated predecessor hash, which the verifier already
    // holds as chain state, so nothing about it is transported. A witness blob is
    // now framing plus signatures and nothing else.
    assert_eq!(
        u64::from_le_bytes(bytes[0..WITNESS_PREFIX_LEN].try_into().unwrap()),
        2,
        "count is a u64 little-endian prefix, and is now the WHOLE framing"
    );
    assert_eq!(
        bytes.len(),
        WITNESS_PREFIX_LEN + 2 * sig_len,
        "exact count + 2 signatures — no r"
    );
    assert_eq!(
        &bytes[WITNESS_PREFIX_LEN..WITNESS_PREFIX_LEN + sig_len],
        &sa.to_canonical_bytes().unwrap()[..],
        "first signature placed immediately after the framing"
    );
    assert_eq!(
        &bytes[WITNESS_PREFIX_LEN + sig_len..],
        &sb.to_canonical_bytes().unwrap()[..],
        "second signature follows, in order"
    );

    // Round-trips back to the same witness.
    assert_eq!(
        BlockAttestationWitness::from_canonical_bytes(&bytes).unwrap(),
        witness_two_sig()
    );
}

#[test]
fn witness_decode_rejects_corruption_of_the_pin() {
    let good = witness_two_sig().to_canonical_bytes().unwrap();
    let sig_len = HybridSignature::CANONICAL_LEN;

    // (1) Flip one byte of the FIRST SIGNATURE: decodes, but to a DIFFERENT
    //     witness. This arm used to flip `r`; with `r` gone (RF-D3) the leading
    //     bytes are the count, and flipping those is the length-mismatch arm
    //     below rather than a content-binding arm. Retargeted onto signature
    //     bytes so the arm still tests what it was written to test — that
    //     content is bound — instead of quietly becoming a duplicate of (2).
    let mut sig_flip = good.clone();
    sig_flip[WITNESS_PREFIX_LEN] ^= 0x01;
    // Either outcome is a rejection of the corrupted blob: it decodes to a
    // DIFFERENT witness (content is bound), or it fails to decode at all (the
    // flipped byte landed in a field the signature codec validates). Asserting
    // only the first would make the arm depend on which byte the flip hits.
    assert!(
        !matches!(
            BlockAttestationWitness::from_canonical_bytes(&sig_flip),
            Ok(ref w) if *w == witness_two_sig()
        ),
        "a flipped signature byte must not decode to the pinned witness"
    );

    // (2) Bump the count field without adding a signature: the derive-on-encode /
    // validate-on-decode guard rejects the disagreement loudly.
    let mut count_bump = good.clone();
    count_bump[0..WITNESS_PREFIX_LEN].copy_from_slice(&3u64.to_le_bytes());
    assert!(
        matches!(
            BlockAttestationWitness::from_canonical_bytes(&count_bump),
            Err(WitnessError::LengthMismatch { .. })
        ),
        "count disagreeing with the signature-array length must be LengthMismatch"
    );

    // (3) Swap the two signature blocks: decodes to reversed order (!= original), so
    // signature ORDER (the pairing input) is bound, not just the set.
    let mut swapped = good.clone();
    let (_, sigs) = swapped.split_at_mut(WITNESS_PREFIX_LEN);
    let (a, b) = sigs.split_at_mut(sig_len);
    a.swap_with_slice(b);
    assert_ne!(
        BlockAttestationWitness::from_canonical_bytes(&swapped).unwrap(),
        witness_two_sig(),
        "swapping the two signatures must change the decoded witness"
    );
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
