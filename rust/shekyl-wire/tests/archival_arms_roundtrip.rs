// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival input-arm serializer tests (dense tags: `serve_credit` 0x02, `bond_post` 0x03).
//!
//! These arms are **Shekyl-native** — there is no C++ oracle (the C++/`bond_wire`
//! impl is incomplete; notably it omits `bond_spend_pk`), so the design docs +
//! Rust impl are authority and the test is a synthetic round-trip
//! (`read(write(x)) == x`). Layouts transcribed from
//! `shekyl-archival-retention::{wire,bond_wire}` + GENESIS_TX_WIRE_FORMAT.md
//! §9.10/§9.11, with `bond_spend_pk` added per §9.11.

use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::{
    ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES, BOND_POST_KIND_JOINMARKET, PQC_HYBRID_SINGLE_KEY_LEN,
    TAG_INPUT_SERVE_CREDIT,
};
use shekyl_wire::{BondPost, BondPostKind, Holdings, Input};

fn round_trip(input: &Input) -> Input {
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write input arm");
    let mut cursor = &bytes[..];
    let parsed = Input::read(&mut cursor).expect("read input arm");
    assert!(cursor.is_empty(), "input arm left trailing bytes");
    parsed
}

/// A well-shaped opaque kept-half blob: the retention codec's encoding is
/// `tag ‖ p_id(32) ‖ shard ‖ epoch ‖ ed25519(64)`; this crate only checks
/// the tag and the ceiling, so any bytes of that shape exercise the arm.
fn kept_blob() -> Vec<u8> {
    let mut b = vec![TAG_INPUT_SERVE_CREDIT];
    b.extend_from_slice(&[0x11; 32]);
    b.extend_from_slice(&[7, 42]);
    b.extend_from_slice(&[0x66; 64]);
    b
}

#[test]
fn serve_credit_round_trips() {
    // The KEPT half, as the opaque blob the C++ vin transports (RF-D1 /
    // rule 40). The interior is `shekyl-archival-retention::wire`'s; this
    // arm mirrors the emission arm: tag + length + bytes.
    let input = Input::ServeCredit {
        canonical_bytes: kept_blob(),
    };
    assert_eq!(round_trip(&input), input);
}

#[test]
fn serve_credit_blob_must_lead_with_its_tag() {
    let mut bytes = kept_blob();
    bytes[0] = 0x03;
    let input = Input::ServeCredit {
        canonical_bytes: bytes,
    };
    let mut out = Vec::new();
    input
        .write(&mut out)
        .expect("write encodes without validating");
    let err = Input::read(&mut &out[..]).expect_err("wrong leading tag must reject at read");
    assert!(
        err.to_string().contains("wire tag"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_credit_blob_is_bounded() {
    let mut bytes = kept_blob();
    bytes.resize(ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES + 1, 0);
    let input = Input::ServeCredit {
        canonical_bytes: bytes,
    };
    let mut out = Vec::new();
    input
        .write(&mut out)
        .expect("write encodes without validating");
    assert!(
        Input::read(&mut &out[..]).is_err(),
        "over-ceiling blob must reject at read"
    );
}

#[test]
fn bond_post_holdings_with_duplicate_shard_rejected_at_read() {
    // "A set on the wire": the retention decoder (bond_wire::ShardSet) rejects a
    // repeated holdings id; this oracle enforces the same rule independently, so
    // the two decoders cannot diverge on validity. `write` does not validate
    // (it just encodes the caller's vec), so a duplicate-carrying blob is
    // constructible — `read` must reject it.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xAB; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes([0x77; 32]),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk: None,
            endpoint: [0xEE; 32],
        },
        holdings: Holdings::ShardSetCompact(vec![7, 42, 7]),
        bonded_total_atomic: 750_000_000 * 3,
        bond_credit: 750_000_000 * 3,
        bond_debit: 0,
    }));
    let mut bytes = Vec::new();
    input
        .write(&mut bytes)
        .expect("write encodes without validating");
    let err = Input::read(&mut &bytes[..]).expect_err("duplicate holdings must reject at read");
    assert!(
        err.to_string().contains("appears more than once"),
        "unexpected error: {err}"
    );
}

#[test]
fn bond_post_joinmarket_round_trips_with_bond_spend_pk() {
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xAB; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes([0x77; 32]),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk: None,
            endpoint: [0xEE; 32],
        },
        holdings: Holdings::ShardSetCompact(vec![1, 2, 3, 9]),
        bonded_total_atomic: 750_000_000 * 4,
        bond_credit: 750_000_000 * 4,
        bond_debit: 0,
    }));
    let parsed = round_trip(&input);
    assert_eq!(parsed, input);
    // bond_spend_pk survived (the field the current impl omits).
    match parsed {
        Input::BondPost(bp) => assert!(matches!(bp.kind, BondPostKind::JoinMarket { .. })),
        _ => panic!("expected BondPost"),
    }
}

#[test]
fn bond_post_non_joinmarket_has_no_bond_spend_pk() {
    // post_kind 3 was HoldingsUpdate (REJECTED); the envelope still carries
    // Other(tag) without bond_spend_pk. Retention decode refuses the tag.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes([0x02; 32]),
        kind: BondPostKind::Other(3),
        holdings: Holdings::CompleteTree, // carries no shard list
        bonded_total_atomic: 12_000_000_000,
        bond_credit: 9_000_000_000,
        bond_debit: 3_000_000_000,
    }));
    assert_eq!(round_trip(&input), input);
}

#[test]
fn bond_post_other_must_not_reuse_joinmarket_tag() {
    // The JoinMarket coupling is now structural: `JoinMarket` always carries
    // bond_spend_pk (the old "JoinMarket without bond_spend_pk" state is now
    // unrepresentable — a compile-time guarantee, not a runtime check). The only
    // residual misuse — `Other` reusing the JoinMarket tag, which would emit a blob
    // that re-reads as a JoinMarket post — is rejected at write.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes([0x02; 32]),
        kind: BondPostKind::Other(BOND_POST_KIND_JOINMARKET),
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 1,
        bond_credit: 1,
        bond_debit: 0,
    }));
    let mut bytes = Vec::new();
    let err = input
        .write(&mut bytes)
        .expect_err("Other must not use the JoinMarket tag");
    assert!(err.to_string().contains("JoinMarket"), "unexpected: {err}");
}

// ---- the JoinMarket's two wire forms (FN-DSA increment 3) ------------------
//
// `post_kind` 0 is the JoinMarket as it has always been; `post_kind` 5 is the
// same post with the persona's receipt key between `bond_spend_pk` and the
// endpoint. The expected bytes below are assembled by hand from the layout,
// never by an encoder, so they hold both encoders to the layout and to each
// other. No pre-existing byte fixture of a kind-0 post was on file; the
// hand-assembled layout is the one the crate header transcribes.

use shekyl_archival_retention::{
    ArchivalBondPostVin, BondKind, BondPostKind as RetentionKind, BondWireError,
    HoldingsDescriptor, HoldingsKind, ShardSet, RECEIPT_SIGN_PK_CANONICAL_BYTES,
};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_wire::transaction::{
    is_join_market_post_kind, BOND_POST_KIND_JOINMARKET_RECEIPT, BOND_POST_RECEIPT_KEY_LEN,
    TAG_INPUT_BOND_POST,
};

const IDENTITY: u8 = 0xAB;
const SPEND: u8 = 0xCD;
const RECEIPT: u8 = 0x5C;
const HINT: [u8; 32] = [0x77; 32];
const ENDPOINT: [u8; 32] = [0xEE; 32];
const SHARDS: [u64; 4] = [1, 2, 3, 300];
const TOTAL: u64 = 750_000_000 * 4;

/// LEB128, written out here so the expected bytes share no code with either
/// encoder under test.
fn leb128(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let low = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// The whole vin by hand: tag, identity key, hint, kind byte, the kind's
/// coupled fields, holdings, the three amounts. `receipt_len` is the length
/// the receipt key's prefix declares and the number of bytes that follow it.
fn join_market_bytes(kind: u8, receipt_len: Option<usize>) -> Vec<u8> {
    let mut b = vec![TAG_INPUT_BOND_POST];
    leb128(PQC_HYBRID_SINGLE_KEY_LEN as u64, &mut b);
    b.extend(std::iter::repeat_n(IDENTITY, PQC_HYBRID_SINGLE_KEY_LEN));
    b.extend_from_slice(&HINT);
    b.push(kind);
    leb128(PQC_HYBRID_SINGLE_KEY_LEN as u64, &mut b);
    b.extend(std::iter::repeat_n(SPEND, PQC_HYBRID_SINGLE_KEY_LEN));
    if let Some(len) = receipt_len {
        leb128(len as u64, &mut b);
        b.extend(std::iter::repeat_n(RECEIPT, len));
    }
    b.extend_from_slice(&ENDPOINT);
    b.push(0); // holdings kind: compact shard set
    leb128(SHARDS.len() as u64, &mut b);
    for shard in SHARDS {
        leb128(shard, &mut b);
    }
    leb128(TOTAL, &mut b); // bonded_total_atomic
    leb128(TOTAL, &mut b); // bond_credit
    leb128(0, &mut b); // bond_debit
    b
}

fn wire_join(receipt_sign_pk: Option<Vec<u8>>) -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![IDENTITY; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes(HINT),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![SPEND; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk,
            endpoint: ENDPOINT,
        },
        holdings: Holdings::ShardSetCompact(SHARDS.to_vec()),
        bonded_total_atomic: TOTAL,
        bond_credit: TOTAL,
        bond_debit: 0,
    }))
}

fn retention_join(receipt_sign_pk: Option<Vec<u8>>) -> ArchivalBondPostVin {
    ArchivalBondPostVin {
        hybrid_public_key: vec![IDENTITY; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: HINT,
        kind: BondKind::JoinMarket {
            bond_spend_pk: vec![SPEND; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk,
            endpoint: ENDPOINT,
        },
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(SHARDS.to_vec()).expect("distinct shards"),
        },
        bonded_total_atomic: TOTAL,
        bond_credit: TOTAL,
        bond_debit: 0,
    }
}

fn written(input: &Input) -> Vec<u8> {
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write input arm");
    bytes
}

/// The receipt key's length has three names — this crate's restated constant,
/// the retention crate's, and the key type's own — and one value.
#[test]
fn the_receipt_key_length_is_its_twin_s() {
    assert_eq!(
        BOND_POST_RECEIPT_KEY_LEN,
        FnDsaHybridPublicKey::CANONICAL_LEN
    );
    assert_eq!(BOND_POST_RECEIPT_KEY_LEN, RECEIPT_SIGN_PK_CANONICAL_BYTES);
    assert_eq!(BOND_POST_RECEIPT_KEY_LEN, 1_837);
}

/// The receipt-key JoinMarket's byte is 5 in both crates, and the bytes two
/// rulings refused — 3 (`HoldingsUpdate`) and 4 (`EndpointUpdate`) — are
/// neither it nor a JoinMarket.
#[test]
fn the_receipt_join_market_byte_is_five_and_the_refused_bytes_stay_refused() {
    assert_eq!(BOND_POST_KIND_JOINMARKET_RECEIPT, 5);
    assert_eq!(
        RetentionKind::JoinMarketReceipt as u8,
        BOND_POST_KIND_JOINMARKET_RECEIPT
    );
    assert_eq!(RetentionKind::JoinMarket as u8, BOND_POST_KIND_JOINMARKET);
    for kind in 0..=u8::MAX {
        assert_eq!(
            is_join_market_post_kind(kind),
            kind == 0 || kind == 5,
            "kind {kind}"
        );
        assert_eq!(
            RetentionKind::from_u8(kind).is_ok_and(RetentionKind::is_join_market),
            kind == 0 || kind == 5,
            "kind {kind}"
        );
    }
    for refused in [3u8, 4] {
        assert!(matches!(
            RetentionKind::from_u8(refused),
            Err(BondWireError::InvalidPostKind(b)) if b == refused
        ));
    }
}

/// Kind 0 is untouched: both encoders emit exactly the layout it has always
/// had, and both decoders read it back as a JoinMarket with no receipt key.
#[test]
fn a_keyless_join_market_is_byte_for_byte_the_kind_0_layout() {
    let expected = join_market_bytes(0, None);
    let wire = wire_join(None);
    let retention = retention_join(None);
    assert_eq!(written(&wire), expected);
    assert_eq!(retention.serialize().expect("serialize"), expected);

    assert_eq!(Input::read(&mut &expected[..]).expect("wire read"), wire);
    let decoded = ArchivalBondPostVin::read(&mut &expected[..]).expect("retention read");
    assert_eq!(decoded, retention);
    assert_eq!(decoded.post_kind(), RetentionKind::JoinMarket);
    assert_eq!(decoded.receipt_sign_pk(), None);
}

/// Kind 5 round-trips in both representations, and the two agree byte for
/// byte on one post: kind 0's fields with the length-prefixed receipt key
/// between `bond_spend_pk` and the endpoint.
#[test]
fn a_receipt_join_market_round_trips_and_both_representations_agree() {
    let key = vec![RECEIPT; BOND_POST_RECEIPT_KEY_LEN];
    let expected = join_market_bytes(5, Some(BOND_POST_RECEIPT_KEY_LEN));
    let wire = wire_join(Some(key.clone()));
    let retention = retention_join(Some(key.clone()));

    let wire_bytes = written(&wire);
    let retention_bytes = retention.serialize().expect("serialize");
    assert_eq!(wire_bytes, expected);
    assert_eq!(retention_bytes, expected);
    // The receipt form is the keyless form plus the prefix and the key.
    assert_eq!(
        expected.len(),
        join_market_bytes(0, None).len() + 2 + BOND_POST_RECEIPT_KEY_LEN
    );

    let parsed = round_trip(&wire);
    assert_eq!(parsed, wire);
    match parsed {
        Input::BondPost(post) => match post.kind {
            BondPostKind::JoinMarket {
                receipt_sign_pk, ..
            } => assert_eq!(receipt_sign_pk.as_deref(), Some(&key[..])),
            BondPostKind::Other(tag) => panic!("kind 5 surfaced as Other({tag})"),
        },
        other => panic!("expected a bond post, read {other:?}"),
    }

    let decoded = ArchivalBondPostVin::read(&mut &expected[..]).expect("retention read");
    assert_eq!(decoded, retention);
    assert_eq!(decoded.post_kind(), RetentionKind::JoinMarketReceipt);
    assert!(decoded.kind.is_join_market());
    assert_eq!(decoded.receipt_sign_pk(), Some(&key[..]));
    assert_eq!(decoded.bond_spend_pk(), retention.bond_spend_pk());
    assert_eq!(decoded.endpoint(), Some(&ENDPOINT));
}

/// A receipt key of any length but the canonical one is refused by both
/// decoders at the length prefix — one short, one long, and empty.
#[test]
fn a_receipt_key_of_the_wrong_length_is_refused_at_read_by_both_decoders() {
    for len in [
        0,
        BOND_POST_RECEIPT_KEY_LEN - 1,
        BOND_POST_RECEIPT_KEY_LEN + 1,
    ] {
        let bytes = join_market_bytes(5, Some(len));
        let err = Input::read(&mut &bytes[..]).expect_err("wire refuses the length");
        assert!(
            err.to_string().contains("receipt_sign_pk length"),
            "len {len}: {err}"
        );
        assert!(
            matches!(
                ArchivalBondPostVin::read(&mut &bytes[..]),
                Err(BondWireError::ReceiptSignPkLenNotCanonical { got }) if got == len
            ),
            "len {len}"
        );
    }
}

/// The retention writer refuses a hand-built receipt key of the wrong length
/// (`check_couplings`), as it refuses a wrong-length `bond_spend_pk`.
#[test]
fn the_retention_writer_refuses_a_receipt_key_of_the_wrong_length() {
    let vin = retention_join(Some(vec![RECEIPT; BOND_POST_RECEIPT_KEY_LEN - 1]));
    assert!(matches!(
        vin.serialize(),
        Err(BondWireError::ReceiptSignPkLenNotCanonical { got })
            if got == BOND_POST_RECEIPT_KEY_LEN - 1
    ));
}

/// `Other` carrying the receipt JoinMarket's tag is the misconstruction
/// `Other(0)` is: `write` would emit a blob with no keys and no endpoint that
/// `read` parses as a JoinMarket. Refused at the writer, with the same words.
#[test]
fn bond_post_other_must_not_reuse_the_receipt_joinmarket_tag() {
    let other = |tag| {
        Input::BondPost(Box::new(BondPost {
            hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
            p_canonical_id: PCanonicalId::from_bytes([0x02; 32]),
            kind: BondPostKind::Other(tag),
            holdings: Holdings::CompleteTree,
            bonded_total_atomic: 1,
            bond_credit: 1,
            bond_debit: 0,
        }))
    };
    let refusal = |tag| {
        other(tag)
            .write(&mut Vec::new())
            .expect_err("Other must not use a JoinMarket tag")
            .to_string()
    };
    assert_eq!(
        refusal(BOND_POST_KIND_JOINMARKET_RECEIPT),
        refusal(BOND_POST_KIND_JOINMARKET)
    );
    assert!(refusal(BOND_POST_KIND_JOINMARKET_RECEIPT).contains("JoinMarket"));
    // The refused bytes 3 and 4 are not JoinMarket tags: `Other` carries them
    // on this envelope, and the retention decoder refuses them.
    for tag in [3u8, 4] {
        assert_eq!(round_trip(&other(tag)), other(tag));
    }
}
