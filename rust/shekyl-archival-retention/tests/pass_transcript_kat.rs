// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-pinned vectors for the SF-D8 pass transcript a persona's receipt
//! key signs (`ARCHIVAL_SHARD_FETCH.md` `SF-D8`): the decoded request
//! header, the transcript, the delivery digest, and the constants that
//! size them.
//!
//! Oracle tiers (rule 50). The header and transcript pins are
//! **hand-computed (tier 1)**: byte concatenations checkable by eye. The
//! delivery-digest values are **independent (tier 2)**: taken from a
//! standalone Keccak-f[1600] / SP 800-185 cSHAKE256 written for the
//! purpose and checked against NIST's cSHAKE256 samples #3 and #4, not from
//! this crate.
//!
//! The pin is over the **decoded** 73-byte header in canonical binary
//! (`SF-D8` clarification): the textual header encoding `RF-R1` owns never
//! enters the transcript.

use shekyl_archival_retention::{
    pass_countersignature_message, pass_delivery_digest, pass_request_header_bytes, PassStream,
    PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_HEIGHT_LEN, PASS_ANCHOR_LAG_BLOCKS,
    PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_DELIVERY_DIGEST_CUSTOMIZATION,
    PASS_DELIVERY_DIGEST_LEN, PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN,
};
use shekyl_types::{BlockCount, BlockHeight};

fn bh(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// The anchor depth IS the segment-freeze margin (`segment.rs`): the pass
/// anchors at the depth segment freeze already relies on never being
/// replaced, so the anchored hash is canonical on every honest node. If
/// either constant moves without the other, this is where it fails.
const _: () = assert!(
    shekyl_curve_tree::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS == PASS_ANCHOR_DEPTH_BLOCKS.to_raw(),
    "pass anchor depth must equal the segment-freeze reorg margin"
);

const MSG_NONCE: [u8; PASS_NONCE_LEN] = [0x03; 32];
const MSG_ANCHOR_HEIGHT: u64 = 0x0102_0304_0506_0708;
const MSG_ANCHOR_HASH: [u8; PASS_ANCHOR_HASH_LEN] = [0x04; 32];
const MSG_SHARD: u64 = 5;
/// The framed response body the digest vectors hash: the 48 bytes
/// `0x01..=0x30`. A stand-in for `RF-D4` frame ‖ payload; the digest does
/// not parse it.
const FRAMED: [u8; 48] = {
    let mut out = [0u8; 48];
    let mut i = 0;
    let mut byte = 1u8;
    while i < 48 {
        out[i] = byte;
        byte += 1;
        i += 1;
    }
    out
};
/// `cSHAKE256("shekyl/archival-pass-delivery-digest-v1", [0x03;32] ‖ FRAMED)[..32]`,
/// from the independent implementation (module docs).
const MSG_DIGEST_EXPECT_HEX: &str =
    "0758cedb256259dd3d372560884dcaec515857360ed434155bae0bbb4c85a6bb";
/// `cSHAKE256(label, [0xC4;32] ‖ FRAMED)[..32]`, from the independent
/// implementation.
const SECOND_NONCE: [u8; PASS_NONCE_LEN] = [0xC4; 32];
const SECOND_DIGEST_EXPECT_HEX: &str =
    "6ad2a8206b1eabfe466d1b6da47518922b2cb638a830ffbf4b945d1b43106d58";
/// The decoded request header: stream `00` ‖ `[0x03;32]` ‖ anchor height
/// little-endian (`0807060504030201`) ‖ `[0x04;32]`. Hand-computed.
const REQUEST_HEADER_EXPECT_HEX: &str = concat!(
    "00",
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0807060504030201",
    "0404040404040404040404040404040404040404040404040404040404040404",
);
/// The transcript: the decoded header ‖ shard little-endian
/// (`0500000000000000`) ‖ the delivery digest ([`MSG_DIGEST_EXPECT_HEX`]).
/// Hand-computed: a plain concatenation of fixed-width fields, **not** a
/// hash of them — a verifier that hashed it would fail here.
const MSG_EXPECT_HEX: &str = concat!(
    "00",
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0807060504030201",
    "0404040404040404040404040404040404040404040404040404040404040404",
    "0500000000000000",
    "0758cedb256259dd3d372560884dcaec515857360ed434155bae0bbb4c85a6bb",
);

#[test]
fn request_header_and_transcript_match_pin() {
    let hdr = pass_request_header_bytes(
        PassStream::Economy,
        &MSG_NONCE,
        bh(MSG_ANCHOR_HEIGHT),
        &MSG_ANCHOR_HASH,
    );
    assert_eq!(hdr.len(), PASS_REQUEST_HEADER_LEN);
    assert_eq!(hex::encode(hdr), REQUEST_HEADER_EXPECT_HEX);

    let digest = pass_delivery_digest(&MSG_NONCE, &FRAMED);
    assert_eq!(hex::encode(digest), MSG_DIGEST_EXPECT_HEX);
    let msg = pass_countersignature_message(
        PassStream::Economy,
        &MSG_NONCE,
        bh(MSG_ANCHOR_HEIGHT),
        &MSG_ANCHOR_HASH,
        MSG_SHARD,
        &digest,
    );
    assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
    assert_eq!(hex::encode(msg), MSG_EXPECT_HEX);
}

/// The delivery digest against the independent implementation, at the
/// vectors that fix its shape: an empty body (the preimage is the nonce
/// alone) and a short one under two nonces.
#[test]
fn delivery_digest_matches_the_independent_vectors() {
    assert_eq!(
        hex::encode(pass_delivery_digest(&MSG_NONCE, &[])),
        "383cb87634c654105464750338339c6e4d88260a46599eac0e46ef09a9ac9806"
    );
    assert_eq!(
        hex::encode(pass_delivery_digest(&MSG_NONCE, &FRAMED)),
        MSG_DIGEST_EXPECT_HEX
    );
    assert_eq!(
        hex::encode(pass_delivery_digest(&SECOND_NONCE, &FRAMED)),
        SECOND_DIGEST_EXPECT_HEX
    );
    assert_eq!(
        PASS_DELIVERY_DIGEST_CUSTOMIZATION,
        b"shekyl/archival-pass-delivery-digest-v1"
    );
}

/// Genesis-frozen consensus values, pinned as literals: a change is a
/// deliberate consensus edit, so it must move this tripwire.
#[test]
fn pass_constants_are_pinned() {
    assert_eq!(PASS_NONCE_LEN, 32);
    assert_eq!(PASS_ANCHOR_HEIGHT_LEN, 8);
    assert_eq!(PASS_ANCHOR_HASH_LEN, 32);
    assert_eq!(PASS_REQUEST_HEADER_LEN, 73);
    assert_eq!(PASS_DELIVERY_DIGEST_LEN, 32);
    assert_eq!(PASS_COUNTERSIGNATURE_MESSAGE_LEN, 113);
    // The anchor: depth from the generated reorg-depth constant, lag
    // PROVISIONAL 4 (the JSON key carries the falsifier).
    assert_eq!(PASS_ANCHOR_DEPTH_BLOCKS, BlockCount::from_raw(720));
    assert_eq!(PASS_ANCHOR_LAG_BLOCKS, BlockCount::from_raw(4));
}
