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
            receipt_sign_pk: shekyl_types::archival::ReceiptSignPk::from_bytes(
                [0x5c; shekyl_types::archival::RECEIPT_SIGN_PK_LEN],
            ),
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
            receipt_sign_pk: shekyl_types::archival::ReceiptSignPk::from_bytes(
                [0x5c; shekyl_types::archival::RECEIPT_SIGN_PK_LEN],
            ),
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

// ---- the JoinMarket's one wire form (FN-DSA increment 3) -------------------
//
// `post_kind` 5 is the JoinMarket: `bond_spend_pk`, then the persona's
// receipt key, then the endpoint. `post_kind` 0 — the keyless JoinMarket —
// is retired and refused at parse. The expected bytes below are assembled by
// hand from the layout, never by an encoder, so they hold both encoders to
// the layout and to each other.

use shekyl_archival_retention::{
    ArchivalBondPostVin, BondKind, BondPostKind as RetentionKind, BondWireError,
    HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_types::archival::{ReceiptSignPk, RECEIPT_SIGN_PK_LEN};
use shekyl_wire::transaction::{
    is_join_market_post_kind, RetiredKeylessJoinMarket, BOND_POST_KIND_RETIRED_KEYLESS_JOINMARKET,
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

/// The whole vin by hand: tag, identity key, hint, kind byte, the coupled
/// fields, holdings, the three amounts. `receipt_len` is the length the
/// receipt key's prefix declares and the number of bytes that follow it;
/// `None` writes no receipt key at all (the retired keyless layout).
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

fn receipt_key() -> ReceiptSignPk {
    ReceiptSignPk::from_bytes([RECEIPT; RECEIPT_SIGN_PK_LEN])
}

fn wire_join() -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![IDENTITY; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: PCanonicalId::from_bytes(HINT),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![SPEND; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk: receipt_key(),
            endpoint: ENDPOINT,
        },
        holdings: Holdings::ShardSetCompact(SHARDS.to_vec()),
        bonded_total_atomic: TOTAL,
        bond_credit: TOTAL,
        bond_debit: 0,
    }))
}

fn retention_join() -> ArchivalBondPostVin {
    ArchivalBondPostVin {
        hybrid_public_key: vec![IDENTITY; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: HINT,
        kind: BondKind::JoinMarket {
            bond_spend_pk: vec![SPEND; PQC_HYBRID_SINGLE_KEY_LEN],
            receipt_sign_pk: receipt_key(),
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

/// The receipt key's length has two names — `RECEIPT_SIGN_PK_LEN` and
/// `FnDsaHybridPublicKey::CANONICAL_LEN` — and one value.
#[test]
fn the_receipt_key_length_is_its_twin_s() {
    assert_eq!(RECEIPT_SIGN_PK_LEN, FnDsaHybridPublicKey::CANONICAL_LEN);
    assert_eq!(RECEIPT_SIGN_PK_LEN, 1_837);
    assert_eq!(receipt_key().as_bytes().len(), RECEIPT_SIGN_PK_LEN);
}

/// The JoinMarket's byte is 5 in both crates and it is the only JoinMarket
/// byte. The bytes three rulings refused — 0 (the keyless JoinMarket), 3
/// (`HoldingsUpdate`) and 4 (`EndpointUpdate`) — are neither it nor a
/// JoinMarket, and the retention table refuses each.
///
/// Why the byte has two definitions, tied here at run time rather than by
/// one `const`: `shekyl-wire` (`BOND_POST_KIND_JOINMARKET`) and
/// `shekyl-archival-retention` (`BondPostKind::JoinMarket = 5`) have no
/// runtime edge between them — the wire's dependency on the retention
/// crate is dev-only, by design (`shekyl-wire/Cargo.toml`), and the
/// retention crate does not depend on the wire — so neither can import the
/// other's constant. Their shared root is `shekyl-types`, which carries no
/// bond-post discriminant; this test is what holds the two to one value.
#[test]
fn the_join_market_byte_is_five_and_the_refused_bytes_stay_refused() {
    assert_eq!(BOND_POST_KIND_JOINMARKET, 5);
    assert_eq!(BOND_POST_KIND_RETIRED_KEYLESS_JOINMARKET, 0);
    assert_eq!(RetentionKind::JoinMarket as u8, BOND_POST_KIND_JOINMARKET);
    for kind in 0..=u8::MAX {
        assert_eq!(is_join_market_post_kind(kind), kind == 5, "kind {kind}");
        assert_eq!(
            RetentionKind::from_u8(kind).is_ok_and(RetentionKind::is_join_market),
            kind == 5,
            "kind {kind}"
        );
    }
    for refused in [0u8, 3, 4] {
        assert!(matches!(
            RetentionKind::from_u8(refused),
            Err(BondWireError::InvalidPostKind(b)) if b == refused
        ));
    }
}

/// The JoinMarket round-trips in both representations, and the two agree
/// byte for byte on one post: `bond_spend_pk`, the length-prefixed receipt
/// key, the endpoint.
#[test]
fn a_join_market_round_trips_and_both_representations_agree() {
    let expected = join_market_bytes(5, Some(RECEIPT_SIGN_PK_LEN));
    let wire = wire_join();
    let retention = retention_join();

    assert_eq!(written(&wire), expected);
    assert_eq!(retention.serialize().expect("serialize"), expected);

    let parsed = round_trip(&wire);
    assert_eq!(parsed, wire);
    match parsed {
        Input::BondPost(post) => match post.kind {
            BondPostKind::JoinMarket {
                receipt_sign_pk, ..
            } => assert_eq!(receipt_sign_pk, receipt_key()),
            BondPostKind::Other(tag) => panic!("kind 5 surfaced as Other({tag})"),
        },
        other => panic!("expected a bond post, read {other:?}"),
    }

    let decoded = ArchivalBondPostVin::read(&mut &expected[..]).expect("retention read");
    assert_eq!(decoded, retention);
    assert_eq!(decoded.post_kind(), RetentionKind::JoinMarket);
    assert!(decoded.post_kind().is_join_market());
    assert_eq!(decoded.receipt_sign_pk(), Some(&receipt_key()));
    assert_eq!(decoded.bond_spend_pk(), retention.bond_spend_pk());
    assert_eq!(decoded.endpoint(), Some(&ENDPOINT));
}

/// `post_kind` 0, the keyless JoinMarket, is refused at parse by both
/// decoders — the exact bytes the retired form had (its coupled fields with
/// no receipt key), and the JoinMarket's own bytes with the kind byte set
/// back to 0. Neither surfaces as `Other(0)`.
#[test]
fn the_retired_keyless_join_market_is_refused_at_parse() {
    for bytes in [
        join_market_bytes(0, None),
        join_market_bytes(0, Some(RECEIPT_SIGN_PK_LEN)),
    ] {
        let err = Input::read(&mut &bytes[..]).expect_err("the wire refuses post_kind 0");
        assert!(
            err.get_ref()
                .is_some_and(RetiredKeylessJoinMarket::downcast_is),
            "{err}"
        );
        assert!(matches!(
            ArchivalBondPostVin::read(&mut &bytes[..]),
            Err(BondWireError::InvalidPostKind(0))
        ));
    }
    // And a JoinMarket (kind 5) with no receipt key where one belongs does
    // not parse: the endpoint's first bytes are not the key's length prefix.
    let keyless_under_5 = join_market_bytes(5, None);
    assert!(Input::read(&mut &keyless_under_5[..]).is_err());
    assert!(ArchivalBondPostVin::read(&mut &keyless_under_5[..]).is_err());
}

/// A receipt key of any length but the canonical one is refused by both
/// decoders at the length prefix — one short, one long, and empty.
#[test]
fn a_receipt_key_of_the_wrong_length_is_refused_at_read_by_both_decoders() {
    for len in [0, RECEIPT_SIGN_PK_LEN - 1, RECEIPT_SIGN_PK_LEN + 1] {
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

/// `Other` carrying the JoinMarket's tag, or the retired keyless one, is a
/// misconstruction: `write` would emit a blob with no keys and no endpoint
/// that `read` does not read back as the value written. Refused at the
/// writer, with the same words for both.
#[test]
fn bond_post_other_must_not_use_a_join_market_tag_live_or_retired() {
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
        refusal(BOND_POST_KIND_RETIRED_KEYLESS_JOINMARKET),
        refusal(BOND_POST_KIND_JOINMARKET)
    );
    assert!(refusal(BOND_POST_KIND_JOINMARKET).contains("JoinMarket"));
    // The refused bytes 3 and 4 were never JoinMarket tags: `Other` carries
    // them on this envelope, and the retention decoder refuses them.
    for tag in [3u8, 4] {
        assert_eq!(round_trip(&other(tag)), other(tag));
    }
}
