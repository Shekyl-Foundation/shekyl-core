// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-pinned vectors for the credit-wire record format
//! (`ARCHIVAL_CREDIT_WIRE.md` §3, amended by `ARCHIVAL_SHARD_FETCH.md` `SF-D8`):
//! `AttestationHeader::to_canonical_bytes`, `pass_request_header_bytes` /
//! `pass_countersignature_message`, `attestation_root`, the witness encoding,
//! the anchor window (both genesis boundaries), and a **deterministic pinned v2
//! countersignature** that `verify_pass_countersignature` must accept against
//! a pinned anchor-hash window.
//!
//! Oracle tiers (rule 50 — the name is part of the declaration). The header and
//! transcript pins are **hand-computed (tier 1)**: byte concatenations checkable
//! by eye, so they are KATs. The root, witness, and signature fixture
//! (`fixtures/attestation_pass_countersignature_v2_pinned.json`) are
//! **self-pinned (tier 3)**: produced by this crate and frozen, a drift tripwire
//! and not a KAT — which is why every one of them is named `pinned_*`. The
//! signature fixture carries an independent (tier 2) check alongside: the
//! verifier accepts it and rejects every single-term mutation, so sign/verify
//! co-drift cannot pass.
//!
//! These pins are the tripwire the crate's other attestation tests cannot be:
//! every unit test in `attestation_wire.rs` is self-consistent (compute twice,
//! or sign-then-verify), so a changed customization string, a changed scheme
//! domain, a reordered field, or an LE↔BE flip would flip *nothing* red. Here
//! the exact output bytes are frozen, so any such change fails loudly — and
//! these are the same vectors the C++ block-format code differential-tests
//! against over the FFI.
//!
//! The signature vector is deterministic end to end: `P`'s identity keypair is
//! `derive_archival_p_keys` over a fixed master seed, and the ML-DSA leg is
//! signed with a fixed hedging seed, so a rebuild reproduces the pinned
//! signature byte-for-byte — sign/verify co-drift cannot pass here. The pin is
//! over the **decoded** 72-byte header in canonical binary (`SF-D8`
//! clarification): the textual header encoding `RF-R1` owns never enters the
//! transcript, so Rust and C++ cannot disagree on a case or padding variant.
//!
//! Regenerate (armed — cite the `docs/V3_WALLET_DECISION_LOG.md` entry that
//! authorizes moving a consensus pin, rule 50):
//! `SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-archival-retention --test attestation_wire_kat \
//!   regenerate_attestation_wire_vectors -- --ignored --nocapture`
//! It rewrites `tests/fixtures/attestation_pass_countersignature_v2_pinned.json`
//! and prints the inline hex constants to paste below.

use serde_json::{json, Value};
use shekyl_archival_retention::{
    attestation_root, pass_countersignature_message, pass_request_header_bytes,
    verify_pass_countersignature, AttestationHeader, AttestationKind, BlockAttestationWitness,
    PassAnchorWindow, PassAnchorWindowError, PassCountersignatureError, PassRecord, PassWitness,
    WitnessError, ATTESTATION_HEADER_LEN, MAX_ATTESTATION_RECORDS, MAX_ATTESTATION_WITNESS_BYTES,
    PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_HEIGHT_LEN, PASS_ANCHOR_LAG_BLOCKS,
    PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, PASS_ANCHOR_WINDOW_LEN, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
    PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN, WITNESS_ENTRY_LEN, WITNESS_PREFIX_LEN,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
    HYBRID_SCHEME_ID_ED25519_ML_DSA_65, HYBRID_SIG_VERSION, ML_DSA_65_SIGNATURE_LENGTH,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_types::{BlockCount, BlockHeight};

fn bh(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

fn bc(n: u64) -> BlockCount {
    BlockCount::from_raw(n)
}

const SIG_PINNED: &str = include_str!("fixtures/attestation_pass_countersignature_v2_pinned.json");

/// The anchor depth IS the segment-freeze margin (`segment.rs`): the pass
/// countersignature anchors at the depth segment freeze already relies on never
/// being replaced, so the anchored hash is canonical on every honest node. If
/// either constant moves without the other, this is where it fails. (A
/// compile-time assert, not a runtime one: `shekyl-curve-tree` is a
/// dev-dependency here, so the pin lives in the test crate.)
const _: () = assert!(
    shekyl_curve_tree::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS == PASS_ANCHOR_DEPTH_BLOCKS.to_raw(),
    "pass anchor depth must equal the segment-freeze reorg margin"
);

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

// ---- Transcript vector (SF-D8): nonce ‖ anchor_height_le ‖ anchor_hash ‖ shard_le ----
const MSG_NONCE: [u8; PASS_NONCE_LEN] = [0x03; 32];
const MSG_ANCHOR_HEIGHT: u64 = 0x0102_0304_0506_0708;
const MSG_ANCHOR_HASH: [u8; PASS_ANCHOR_HASH_LEN] = [0x04; 32];
const MSG_SHARD: u64 = 5;
/// The decoded request header: `[0x03;32]` ‖ anchor height little-endian
/// (`0807060504030201`) ‖ `[0x04;32]`. Hand-computed.
const REQUEST_HEADER_EXPECT_HEX: &str = concat!(
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0807060504030201",
    "0404040404040404040404040404040404040404040404040404040404040404",
);
/// The transcript: the decoded header ‖ shard little-endian
/// (`0500000000000000`). Hand-computed: a plain concatenation, **not** a hash —
/// a verifier that hashed it would fail here.
const MSG_EXPECT_HEX: &str = concat!(
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0807060504030201",
    "0404040404040404040404040404040404040404040404040404040404040404",
    "0500000000000000",
);

// ---- Root vectors ----
/// Deterministic fill bytes for two dummy pass-signatures (the root serializes
/// canonical bytes only; it never verifies, so fixed fills suffice and keep the
/// vector reproducible where a real ML-DSA signature is randomized).
const SIG_A_ED_FILL: u8 = 0xA1;
const SIG_A_ML_FILL: u8 = 0xA2;
const SIG_B_ED_FILL: u8 = 0xB1;
const SIG_B_ML_FILL: u8 = 0xB2;
const NONCE_A: [u8; PASS_NONCE_LEN] = [0xA3; 32];
const NONCE_B: [u8; PASS_NONCE_LEN] = [0xB3; 32];
const ANCHOR_A: u64 = 0xA4A4_A4A4_A4A4_A4A4;
const ANCHOR_B: u64 = 0xB4B4_B4B4_B4B4_B4B4;
/// **Genesis-frozen.** The empty root is `cSHAKE(customization, count_le(0))`
/// and did not move when the record layout gained the nonce and anchor height
/// (`SF-D8`): the genesis block's header field is this value on every network.
const ROOT_EMPTY_EXPECT_HEX: &str =
    "32b1bcd9532f6f0cad787eeeb126c307cdd6c9712b914fd6ba087d6a36bb7bf2";
// Moved by SF-D8 (2026-09-13): each record is now
// header ‖ nonce ‖ anchor_height_le ‖ signature. A record-layout change is a
// deliberate consensus edit, so it must move this tripwire (it previously moved
// for the HYBRID_SIG_VERSION 1→2 bump and for the withdrawn nonce-only cut).
const ROOT_TWO_EXPECT_HEX: &str =
    "5f54298ed467d98583783b06bd4307cdebcbca9f07bafba86b137656eaa5ba37";

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

/// The two-record root vector: (header A, nonce A, anchor A, dummy A),
/// (header B, nonce B, anchor B, dummy B).
fn two_record_root() -> [u8; 32] {
    let (sa, sb) = dummy_sig_pair();
    attestation_root(&[
        PassRecord {
            p_id: HDR_P_ID,
            shard_id: 1,
            settlement_epoch: 100,
            nonce: NONCE_A,
            anchor_height: bh(ANCHOR_A),
            signature: sa,
        },
        PassRecord {
            p_id: [0x22; 32],
            shard_id: 2,
            settlement_epoch: 200,
            nonce: NONCE_B,
            anchor_height: bh(ANCHOR_B),
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
fn request_header_and_transcript_match_pin() {
    let hdr = pass_request_header_bytes(&MSG_NONCE, bh(MSG_ANCHOR_HEIGHT), &MSG_ANCHOR_HASH);
    assert_eq!(hdr.len(), PASS_REQUEST_HEADER_LEN);
    assert_eq!(hex::encode(hdr), REQUEST_HEADER_EXPECT_HEX);

    let msg = pass_countersignature_message(
        &MSG_NONCE,
        bh(MSG_ANCHOR_HEIGHT),
        &MSG_ANCHOR_HASH,
        MSG_SHARD,
    );
    assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
    assert_eq!(hex::encode(msg), MSG_EXPECT_HEX);
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
    assert_eq!(PASS_NONCE_LEN, 32);
    assert_eq!(PASS_ANCHOR_HEIGHT_LEN, 8);
    assert_eq!(PASS_ANCHOR_HASH_LEN, 32);
    assert_eq!(PASS_REQUEST_HEADER_LEN, 72);
    assert_eq!(PASS_COUNTERSIGNATURE_MESSAGE_LEN, 80);
    // The anchor window: depth from the generated reorg-depth constant, lag
    // PROVISIONAL 4 (the JSON key carries the falsifier), threshold 724.
    assert_eq!(PASS_ANCHOR_DEPTH_BLOCKS, bc(720));
    assert_eq!(PASS_ANCHOR_LAG_BLOCKS, bc(4));
    assert_eq!(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, bh(724));
    assert_eq!(PASS_ANCHOR_WINDOW_LEN, 5);
    // Exact witness maximum = WITNESS_PREFIX_LEN + 256 × (nonce ‖ anchor_height ‖ HybridSignature).
    // Pinned to the literal so a signature-size or entry-layout change surfaces
    // here rather than silently in the coarse C++ cap. SF-D8 (2026-09-13): each
    // entry gained the 32-byte carried nonce and the 8-byte anchor height, so
    // the maximum rose by 256 × 40 over the v1 signature-only layout.
    assert_eq!(WITNESS_PREFIX_LEN, 8);
    assert_eq!(WITNESS_ENTRY_LEN, 32 + 8 + HybridSignature::CANONICAL_LEN);
    assert_eq!(MAX_ATTESTATION_WITNESS_BYTES, 876_808);
    assert_eq!(
        SCHEME_DOMAIN_ATTESTATION,
        b"shekyl/archival-attestation-scheme-v2"
    );
}

// ---- Anchor window: both genesis boundaries (SF-D8 ruling: pin 723 and 724) ----

/// A deterministic stand-in for "the connecting chain's hash at `height`":
/// `height_le ‖ 0xC4 ‖ zeros`. Hand-readable, so the fixture's window table is
/// checkable by eye, and shared with the C++ pinned-vector test through the fixture file.
fn pinned_chain_hash(height: u64) -> [u8; PASS_ANCHOR_HASH_LEN] {
    let mut h = [0u8; PASS_ANCHOR_HASH_LEN];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h[8] = 0xC4;
    h
}

/// The window a block connecting to `predecessor_height` sees, filled from
/// `pinned_chain_hash` — the same table the fixture carries for the pinned height.
fn pinned_window(predecessor_height: u64) -> PassAnchorWindow {
    let pred = bh(predecessor_height);
    let (first, len) = PassAnchorWindow::shape_for_predecessor(pred)
        .unwrap_or_else(|| panic!("predecessor {predecessor_height} has a window"));
    let hashes: Vec<_> = (0..len as u64)
        .map(|i| pinned_chain_hash(first.to_raw() + i))
        .collect();
    PassAnchorWindow::from_table(pred, &hashes).expect("table sized to the window")
}

/// 723 has no window (any pass record is refused there); 724 is the first
/// predecessor with one, and its window bottoms out at height 0. A live-signed
/// record anchored at 0 verifies at 724 and is structurally unverifiable at
/// 723 — the genesis boundary from both sides.
#[test]
fn anchor_window_genesis_boundary_is_pinned_at_723_and_724() {
    assert_eq!(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, bh(724));
    assert_eq!(PassAnchorWindow::shape_for_predecessor(bh(723)), None);
    assert_eq!(
        PassAnchorWindow::from_table(bh(723), &[[0u8; 32]; PASS_ANCHOR_WINDOW_LEN]).unwrap_err(),
        PassAnchorWindowError::BelowThreshold {
            predecessor_height: bh(723)
        }
    );
    let (first, len) = PassAnchorWindow::shape_for_predecessor(bh(724)).expect("724 has a window");
    assert_eq!((first, len), (bh(0), 5));

    let (pk, sk, p_id) = pinned_persona();
    let anchor = 0u64;
    let sig = HybridEd25519MlDsa
        .sign(
            &sk,
            SCHEME_DOMAIN_ATTESTATION,
            &pass_countersignature_message(&[0x09; 32], bh(anchor), &pinned_chain_hash(anchor), 3),
        )
        .expect("sign");
    let rec = PassRecord {
        p_id,
        shard_id: 3,
        settlement_epoch: 1,
        nonce: [0x09; 32],
        anchor_height: bh(anchor),
        signature: sig,
    };
    assert_eq!(
        verify_pass_countersignature(&pinned_window(724), &pk, &rec),
        Ok(())
    );
    // At 725 the window is [1, 5]: anchor 0 has fallen out of the bottom.
    assert_eq!(
        verify_pass_countersignature(&pinned_window(725), &pk, &rec),
        Err(PassCountersignatureError::AnchorOutOfWindow {
            anchor_height: bh(0),
            first: bh(1),
            last: bh(5),
        })
    );
}

// ---- Witness (count ‖ (nonce ‖ anchor_height ‖ signature)*) canonical-encoding vectors ----
//
// The block-hash differential is structurally blind to the witness (it rides no
// hashed field), so this is the freeze for the transport encoding. `count` is
// DERIVED on encode (passes.len()) and VALIDATED on decode (LengthMismatch) —
// there is no redundant stored count field, so no bad state to represent; a
// maintainer must not add one. The deterministic dummy_sig_pair and fixed
// nonces/anchors make every byte a pinned function of the operands, so the
// structural asserts below ARE the byte pin (and name which field drifted),
// with no lockstep encoder/regenerator hazard.

fn witness_two_sig() -> BlockAttestationWitness {
    let (sa, sb) = dummy_sig_pair();
    BlockAttestationWitness {
        passes: vec![
            PassWitness {
                nonce: NONCE_A,
                anchor_height: bh(ANCHOR_A),
                signature: sa,
            },
            PassWitness {
                nonce: NONCE_B,
                anchor_height: bh(ANCHOR_B),
                signature: sb,
            },
        ],
    }
}

#[test]
fn witness_canonical_encoding_is_pinned_by_structure() {
    let bytes = witness_two_sig().to_canonical_bytes().unwrap();
    let sig_len = HybridSignature::CANONICAL_LEN;
    let (sa, sb) = dummy_sig_pair();

    // Structure asserted against the operands directly (not via to_canonical_bytes),
    // so an encoder bug — big-endian count, anchor before the nonce, wrong
    // entry order — fails here.
    assert_eq!(
        u64::from_le_bytes(bytes[0..WITNESS_PREFIX_LEN].try_into().unwrap()),
        2,
        "count is a u64 little-endian prefix, and is the WHOLE framing"
    );
    assert_eq!(
        bytes.len(),
        WITNESS_PREFIX_LEN + 2 * WITNESS_ENTRY_LEN,
        "exact count + 2 × (nonce ‖ anchor_height ‖ signature)"
    );
    let e0 = WITNESS_PREFIX_LEN;
    let e1 = WITNESS_PREFIX_LEN + WITNESS_ENTRY_LEN;
    let sig_off = PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;
    assert_eq!(
        &bytes[e0..e0 + PASS_NONCE_LEN],
        &NONCE_A,
        "first entry's nonce placed immediately after the framing"
    );
    assert_eq!(
        &bytes[e0 + PASS_NONCE_LEN..e0 + sig_off],
        &ANCHOR_A.to_le_bytes(),
        "first entry's anchor height follows its nonce, little-endian"
    );
    assert_eq!(
        &bytes[e0 + sig_off..e0 + sig_off + sig_len],
        &sa.to_canonical_bytes().unwrap()[..],
        "first signature follows its anchor height"
    );
    assert_eq!(&bytes[e1..e1 + PASS_NONCE_LEN], &NONCE_B);
    assert_eq!(
        &bytes[e1 + PASS_NONCE_LEN..e1 + sig_off],
        &ANCHOR_B.to_le_bytes()
    );
    assert_eq!(
        &bytes[e1 + sig_off..],
        &sb.to_canonical_bytes().unwrap()[..],
        "second entry follows, in order"
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
    let sig_off = WITNESS_PREFIX_LEN + PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;

    // (1) Flip one byte of the FIRST NONCE: decodes, but to a DIFFERENT witness
    //     (the nonce is content the codec carries, so it is bound).
    let mut nonce_flip = good.clone();
    nonce_flip[WITNESS_PREFIX_LEN] ^= 0x01;
    assert_ne!(
        BlockAttestationWitness::from_canonical_bytes(&nonce_flip).unwrap(),
        witness_two_sig(),
        "a flipped nonce byte must decode to a different witness"
    );

    // (2) Flip one byte of the FIRST ANCHOR HEIGHT: same — bound content.
    let mut anchor_flip = good.clone();
    anchor_flip[WITNESS_PREFIX_LEN + PASS_NONCE_LEN] ^= 0x01;
    assert_ne!(
        BlockAttestationWitness::from_canonical_bytes(&anchor_flip).unwrap(),
        witness_two_sig(),
        "a flipped anchor-height byte must decode to a different witness"
    );

    // (3) Flip one byte of the FIRST SIGNATURE. Either outcome is a rejection of
    //     the corrupted blob: it decodes to a DIFFERENT witness (content is
    //     bound), or it fails to decode at all (the flipped byte landed in a
    //     field the signature codec validates).
    let mut sig_flip = good.clone();
    sig_flip[sig_off] ^= 0x01;
    assert!(
        !matches!(
            BlockAttestationWitness::from_canonical_bytes(&sig_flip),
            Ok(ref w) if *w == witness_two_sig()
        ),
        "a flipped signature byte must not decode to the pinned witness"
    );

    // (4) Bump the count field without adding an entry: the derive-on-encode /
    // validate-on-decode guard rejects the disagreement loudly.
    let mut count_bump = good.clone();
    count_bump[0..WITNESS_PREFIX_LEN].copy_from_slice(&3u64.to_le_bytes());
    assert!(
        matches!(
            BlockAttestationWitness::from_canonical_bytes(&count_bump),
            Err(WitnessError::LengthMismatch { .. })
        ),
        "count disagreeing with the entry-array length must be LengthMismatch"
    );

    // (5) Swap the two entries: decodes to reversed order (!= original), so
    // entry ORDER (the pairing input) is bound, not just the set.
    let mut swapped = good.clone();
    let (_, entries) = swapped.split_at_mut(WITNESS_PREFIX_LEN);
    let (a, b) = entries.split_at_mut(WITNESS_ENTRY_LEN);
    a.swap_with_slice(b);
    assert_ne!(
        BlockAttestationWitness::from_canonical_bytes(&swapped).unwrap(),
        witness_two_sig(),
        "swapping the two entries must change the decoded witness"
    );

    // (6) The two superseded entry shapes — signature alone (pre-SF-D8) and
    // nonce ‖ signature (the withdrawn nonce-only cut) — are length mismatches,
    // never a silently re-framed witness.
    for prefix in [Vec::new(), NONCE_A.to_vec()] {
        let mut stale = Vec::new();
        stale.extend_from_slice(&1u64.to_le_bytes());
        stale.extend_from_slice(&prefix);
        stale.extend_from_slice(&dummy_sig_pair().0.to_canonical_bytes().unwrap());
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&stale),
            Err(WitnessError::LengthMismatch { count: 1, .. })
        ));
    }
}

// ---- Deterministic pinned v2 countersignature (SF-D8) ----
//
// Every operand is fixed, so the fixture is a pure function of the code: the
// persona keypair derives from MASTER_SEED via `derive_archival_p_keys`, the
// ML-DSA leg is signed with ML_DSA_HEDGE_SEED, and the anchor window's hashes
// are `pinned_chain_hash` over the pinned heights. If sign and verify co-drift (a
// changed domain, a changed transcript layout, a changed nesting) the pinned
// signature stops verifying — the property the self-consistent unit tests
// cannot deliver.

/// Fixed 64-byte master seed for the pinned persona. Test material only.
const MASTER_SEED: [u8; 64] = [0x5A; 64];
const P_SLOT: u32 = 0;
/// Fixed hedging seed for the deterministic ML-DSA leg.
const ML_DSA_HEDGE_SEED: [u8; 32] = [0x7E; 32];
const SIG_NONCE: [u8; PASS_NONCE_LEN] = [0xC4; 32];
/// The connecting block's validated predecessor `h`. Its window is
/// `[h − 724, h − 720]` = `[3518, 3522]`.
const SIG_PREDECESSOR_HEIGHT: u64 = 4_242;
/// The requester's anchor: `tip − depth` for a block at `h + 1`, i.e. the
/// window's upper bound (the nominal no-skew case).
const SIG_ANCHOR_HEIGHT: u64 = SIG_PREDECESSOR_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const SIG_SHARD_ID: u64 = 17;
const SIG_EPOCH: u64 = 6;

fn pinned_persona() -> (HybridPublicKey, HybridSecretKey, [u8; 32]) {
    let keys = derive_archival_p_keys(
        &MASTER_SEED,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        P_SLOT,
    )
    .expect("derive pinned persona");
    let pk_bytes = keys.hybrid_sign_pk.to_canonical_bytes().expect("pk bytes");
    let p_id = *shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey(&pk_bytes).as_bytes();
    (
        keys.hybrid_sign_pk.clone(),
        keys.hybrid_sign_sk.clone(),
        p_id,
    )
}

fn pinned_signature(sk: &HybridSecretKey) -> HybridSignature {
    let msg = pass_countersignature_message(
        &SIG_NONCE,
        bh(SIG_ANCHOR_HEIGHT),
        &pinned_chain_hash(SIG_ANCHOR_HEIGHT),
        SIG_SHARD_ID,
    );
    HybridEd25519MlDsa
        .sign_with_ml_dsa_seed(sk, SCHEME_DOMAIN_ATTESTATION, &msg, &ML_DSA_HEDGE_SEED)
        .expect("deterministic attestation sign")
}

fn pinned_record(p_id: [u8; 32], signature: HybridSignature) -> PassRecord {
    PassRecord {
        p_id,
        shard_id: SIG_SHARD_ID,
        settlement_epoch: SIG_EPOCH,
        nonce: SIG_NONCE,
        anchor_height: bh(SIG_ANCHOR_HEIGHT),
        signature,
    }
}

fn build_signature_document() -> Value {
    let (pk, sk, p_id) = pinned_persona();
    let sig = pinned_signature(&sk);
    let record = pinned_record(p_id, sig.clone());
    let witness = BlockAttestationWitness {
        passes: vec![PassWitness {
            nonce: SIG_NONCE,
            anchor_height: bh(SIG_ANCHOR_HEIGHT),
            signature: sig.clone(),
        }],
    };
    let window = pinned_window(SIG_PREDECESSOR_HEIGHT);
    let table: Vec<String> = (window.first().to_raw()..=window.last().to_raw())
        .map(|h| hex::encode(pinned_chain_hash(h)))
        .collect();
    json!({
        "format_version": 2,
        "description": "Deterministic pinned SF-D8 v2 pass countersignature: P's identity \
                        keypair from derive_archival_p_keys(master_seed, Mainnet, Bip39, p_slot), \
                        ML-DSA leg hedged with ml_dsa_hedge_seed, over the DECODED request header \
                        nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] followed by shard_id_le[8], \
                        under domain_utf8. anchor_window_hashes_hex[i] is the connecting chain's \
                        hash at anchor_window_first_height + i (L + 1 entries, ascending); the \
                        verifier must find anchor_hash there at anchor_height. Consumed by \
                        shekyl-archival-retention/tests/attestation_wire_kat.rs and the FFI/C++ \
                        attestation pinned-vector tests. Rule-50 oracle tier: self-pinned (3).",
        "domain_utf8": String::from_utf8(SCHEME_DOMAIN_ATTESTATION.to_vec()).expect("utf8"),
        "master_seed_hex": hex::encode(MASTER_SEED),
        "p_slot": P_SLOT,
        "ml_dsa_hedge_seed_hex": hex::encode(ML_DSA_HEDGE_SEED),
        "hybrid_public_key_hex": hex::encode(pk.to_canonical_bytes().expect("pk")),
        "p_id_hex": hex::encode(p_id),
        "nonce_hex": hex::encode(SIG_NONCE),
        "predecessor_height": SIG_PREDECESSOR_HEIGHT,
        "anchor_height": SIG_ANCHOR_HEIGHT,
        "anchor_hash_hex": hex::encode(pinned_chain_hash(SIG_ANCHOR_HEIGHT)),
        "anchor_window_first_height": window.first().to_raw(),
        "anchor_window_hashes_hex": table,
        "shard_id": SIG_SHARD_ID,
        "settlement_epoch": SIG_EPOCH,
        "request_header_hex": hex::encode(pass_request_header_bytes(
            &SIG_NONCE, bh(SIG_ANCHOR_HEIGHT), &pinned_chain_hash(SIG_ANCHOR_HEIGHT))),
        "message_hex": hex::encode(record.countersignature_message(&pinned_chain_hash(SIG_ANCHOR_HEIGHT))),
        "header_hex": hex::encode(record.to_header().to_canonical_bytes()),
        "hybrid_signature_hex": hex::encode(sig.to_canonical_bytes().expect("sig")),
        "witness_hex": hex::encode(witness.to_canonical_bytes().expect("witness")),
        "attestation_root_hex": hex::encode(attestation_root(std::slice::from_ref(&record)).expect("root")),
    })
}

fn read_signature_fixture() -> Value {
    serde_json::from_str(SIG_PINNED)
        .expect("attestation_pass_countersignature_v2_pinned.json parses")
}

fn fixture_hex(kat: &Value, key: &str) -> Vec<u8> {
    hex::decode(kat[key].as_str().unwrap_or_else(|| panic!("{key} present"))).expect("valid hex")
}

/// The fixture's anchor window, decoded from `anchor_window_hashes_hex` — the
/// table the FFI and C++ tests marshal, so the verify-side pin below reads the
/// hashes from the file rather than recomputing them.
fn fixture_window(kat: &Value) -> PassAnchorWindow {
    let hashes: Vec<[u8; 32]> = kat["anchor_window_hashes_hex"]
        .as_array()
        .expect("anchor_window_hashes_hex is an array")
        .iter()
        .map(|v| {
            hex::decode(v.as_str().expect("hex string"))
                .expect("valid hex")
                .try_into()
                .expect("32 bytes")
        })
        .collect();
    PassAnchorWindow::from_table(
        bh(kat["predecessor_height"].as_u64().expect("height")),
        &hashes,
    )
    .expect("fixture window is well-formed")
}

/// The pinned operands are the ones this file derives from — a fixture edited
/// by hand (or regenerated from different seeds) fails here before anything
/// else does.
#[test]
fn pinned_v2_signature_fixture_operands_match_this_test() {
    let kat = read_signature_fixture();
    assert_eq!(kat["format_version"].as_u64(), Some(2));
    assert_eq!(
        kat["domain_utf8"].as_str().map(str::as_bytes),
        Some(SCHEME_DOMAIN_ATTESTATION),
        "fixture domain drifted from SCHEME_DOMAIN_ATTESTATION"
    );
    assert_eq!(fixture_hex(&kat, "master_seed_hex"), MASTER_SEED);
    assert_eq!(kat["p_slot"].as_u64(), Some(u64::from(P_SLOT)));
    assert_eq!(
        fixture_hex(&kat, "ml_dsa_hedge_seed_hex"),
        ML_DSA_HEDGE_SEED
    );
    assert_eq!(fixture_hex(&kat, "nonce_hex"), SIG_NONCE);
    assert_eq!(
        kat["predecessor_height"].as_u64(),
        Some(SIG_PREDECESSOR_HEIGHT)
    );
    assert_eq!(kat["anchor_height"].as_u64(), Some(SIG_ANCHOR_HEIGHT));
    assert_eq!(
        fixture_hex(&kat, "anchor_hash_hex"),
        pinned_chain_hash(SIG_ANCHOR_HEIGHT)
    );
    let (first, _) = PassAnchorWindow::shape_for_predecessor(bh(SIG_PREDECESSOR_HEIGHT)).unwrap();
    assert_eq!(
        kat["anchor_window_first_height"].as_u64(),
        Some(first.to_raw())
    );
    let window = fixture_window(&kat);
    assert_eq!(window.first(), first);
    for h in window.first().to_raw()..=window.last().to_raw() {
        assert_eq!(window.hash_at(bh(h)), Some(&pinned_chain_hash(h)));
    }
    assert_eq!(kat["shard_id"].as_u64(), Some(SIG_SHARD_ID));
    assert_eq!(kat["settlement_epoch"].as_u64(), Some(SIG_EPOCH));
}

/// Derivation and signing are deterministic: rebuilding the fixture from its
/// operands reproduces every pinned byte. This is the sign-side pin; a changed
/// nesting, domain, or transcript layout moves `hybrid_signature_hex`.
#[test]
fn pinned_v2_signature_fixture_is_reproduced_byte_for_byte() {
    let kat = read_signature_fixture();
    let rebuilt = build_signature_document();
    for key in [
        "hybrid_public_key_hex",
        "p_id_hex",
        "request_header_hex",
        "message_hex",
        "header_hex",
        "hybrid_signature_hex",
        "witness_hex",
        "attestation_root_hex",
        "anchor_window_hashes_hex",
    ] {
        assert_eq!(
            rebuilt[key], kat[key],
            "{key}: rebuilt value drifted from the pinned fixture"
        );
    }
}

/// The verify-side pin: the pinned signature (decoded from the fixture, not
/// re-signed) is accepted by `verify_pass_countersignature` against the
/// fixture's anchor window, and rejected under every single-term change.
#[test]
fn pinned_v2_signature_verifies_and_is_bound_to_every_term() {
    let kat = read_signature_fixture();
    let pk = HybridPublicKey::from_canonical_bytes(&fixture_hex(&kat, "hybrid_public_key_hex"))
        .expect("pinned pubkey parses");
    let sig = HybridSignature::from_canonical_bytes(&fixture_hex(&kat, "hybrid_signature_hex"))
        .expect("pinned signature parses");
    let mut p_id = [0u8; 32];
    p_id.copy_from_slice(&fixture_hex(&kat, "p_id_hex"));
    let record = pinned_record(p_id, sig);
    let window = fixture_window(&kat);

    assert_eq!(
        verify_pass_countersignature(&window, &pk, &record),
        Ok(()),
        "pinned v2 countersignature must verify against the pinned anchor window"
    );

    // Anchor window, sliding: the SAME record verifies at predecessors h ..= h + L
    // (the accepted replay window), and is AnchorOutOfWindow at h − 1 (anchor
    // above the upper bound: a pre-fetched read) and at h + L + 1 (stale).
    for h in SIG_PREDECESSOR_HEIGHT..=SIG_PREDECESSOR_HEIGHT + PASS_ANCHOR_LAG_BLOCKS.to_raw() {
        assert_eq!(
            verify_pass_countersignature(&pinned_window(h), &pk, &record),
            Ok(()),
            "pinned record must verify at predecessor {h}"
        );
    }
    assert!(matches!(
        verify_pass_countersignature(&pinned_window(SIG_PREDECESSOR_HEIGHT - 1), &pk, &record),
        Err(PassCountersignatureError::AnchorOutOfWindow { .. })
    ));
    assert!(matches!(
        verify_pass_countersignature(
            &pinned_window(SIG_PREDECESSOR_HEIGHT + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1),
            &pk,
            &record
        ),
        Err(PassCountersignatureError::AnchorOutOfWindow { .. })
    ));
    // Anchor hash: a chain whose hash at the anchor height differs (a fork, or a
    // requester who lied to P) rejects the signature — the hash is P's
    // transcript term, checked against the CHAIN's value, never the header's.
    let forked_hashes: Vec<_> = (window.first().to_raw()..=window.last().to_raw())
        .map(|h| {
            let mut x = pinned_chain_hash(h);
            x[9] ^= 0xFF;
            x
        })
        .collect();
    let forked = PassAnchorWindow::from_table(bh(SIG_PREDECESSOR_HEIGHT), &forked_hashes).unwrap();
    assert_eq!(
        verify_pass_countersignature(&forked, &pk, &record),
        Err(PassCountersignatureError::InvalidSignature)
    );
    // Anchor height (carried), moved inside the window: the chain's hash at the
    // new height is not the one signed over.
    let mut moved = record.clone();
    moved.anchor_height = bh(moved.anchor_height.to_raw() - 1);
    assert_eq!(
        verify_pass_countersignature(&window, &pk, &moved),
        Err(PassCountersignatureError::InvalidSignature)
    );
    // Shard: the server-side binding that closes the decoy-route replay.
    let mut other_shard = record.clone();
    other_shard.shard_id += 1;
    assert_eq!(
        verify_pass_countersignature(&window, &pk, &other_shard),
        Err(PassCountersignatureError::InvalidSignature)
    );
    // Nonce: the carried random must be the one signed over.
    let mut other_nonce = record.clone();
    other_nonce.nonce[0] ^= 0x01;
    assert_eq!(
        verify_pass_countersignature(&window, &pk, &other_nonce),
        Err(PassCountersignatureError::InvalidSignature)
    );
    // p_id: binding 1 — the record must name this key's canonical id.
    let mut other_id = record.clone();
    other_id.p_id[0] ^= 0x01;
    assert_eq!(
        verify_pass_countersignature(&window, &pk, &other_id),
        Err(PassCountersignatureError::PIdMismatch)
    );

    // The witness carrying this pass decodes and re-pairs to the pinned root.
    let witness = BlockAttestationWitness::from_canonical_bytes(&fixture_hex(&kat, "witness_hex"))
        .expect("pinned witness decodes");
    let headers = [record.to_header()];
    let records =
        shekyl_archival_retention::pass_records_from_headers_and_witness(&headers, &witness)
            .expect("one pass header, one entry");
    assert_eq!(
        hex::encode(attestation_root(&records).unwrap()),
        kat["attestation_root_hex"].as_str().unwrap()
    );
    assert_eq!(
        verify_pass_countersignature(&window, &pk, &records[0]),
        Ok(())
    );
}

#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regenerate_attestation_wire_vectors() {
    // These are consensus pins (rule 50): the shared guard refuses to move
    // them without a docs/V3_WALLET_DECISION_LOG.md citation.
    let decision =
        shekyl_crypto_pq::test_support::regen_decision_or_refuse("the attestation wire vectors");
    eprintln!("regenerating the attestation wire vectors under decision: {decision}");

    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/attestation_pass_countersignature_v2_pinned.json");
    let doc = build_signature_document();
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());

    let hdr = header(HDR_P_ID, HDR_SHARD_ID, HDR_EPOCH).to_canonical_bytes();
    println!("HDR_EXPECT_HEX            = \"{}\"", hex::encode(hdr));
    println!(
        "REQUEST_HEADER_EXPECT_HEX = \"{}\"",
        hex::encode(pass_request_header_bytes(
            &MSG_NONCE,
            bh(MSG_ANCHOR_HEIGHT),
            &MSG_ANCHOR_HASH
        ))
    );
    println!(
        "MSG_EXPECT_HEX            = \"{}\"",
        hex::encode(pass_countersignature_message(
            &MSG_NONCE,
            bh(MSG_ANCHOR_HEIGHT),
            &MSG_ANCHOR_HASH,
            MSG_SHARD
        ))
    );
    println!(
        "ROOT_EMPTY_EXPECT_HEX     = \"{}\"",
        hex::encode(attestation_root(&[]).unwrap())
    );
    println!(
        "ROOT_TWO_EXPECT_HEX       = \"{}\"",
        hex::encode(two_record_root())
    );
}
