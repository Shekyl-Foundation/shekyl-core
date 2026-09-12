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
        p_canonical_id: [0x77; 32],
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; PQC_HYBRID_SINGLE_KEY_LEN],
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
        p_canonical_id: [0x77; 32],
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; PQC_HYBRID_SINGLE_KEY_LEN],
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
    // post_kind 3 = HoldingsUpdate: bond_spend_pk is absent on the wire.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x02; 32],
        kind: BondPostKind::Other(3),
        holdings: Holdings::CompleteTree, // carries no shard list
        bonded_total_atomic: 12_000_000_000,
        bond_credit: 9_000_000_000,
        bond_debit: 3_000_000_000,
    }));
    assert_eq!(round_trip(&input), input);
}

#[test]
fn bond_post_endpoint_update_round_trips_as_exactly_the_endpoint() {
    // EU-D11: hybrid_public_key ‖ p_canonical_id ‖ post_kind ‖ endpoint and
    // nothing else — the decoded post carries the empty shape by construction.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x02; 32],
        kind: BondPostKind::EndpointUpdate {
            endpoint: [0x4E; 32],
        },
        holdings: Holdings::ShardSetCompact(Vec::new()),
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }));
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write");
    // The kind-4 payload ends 32 bytes after the kind byte: no holdings
    // descriptor, no varints. (1 vin tag + varint len + key + 32 id + 1 kind + 32.)
    let key_len_varint = 2; // PQC_HYBRID_SINGLE_KEY_LEN = 1996 fits two varint bytes
    assert_eq!(
        bytes.len(),
        1 + key_len_varint + PQC_HYBRID_SINGLE_KEY_LEN + 32 + 1 + 32
    );
    assert_eq!(round_trip(&input), input);
}

/// EU-D9 KAT (a) at this serializer: a kind-4 post carrying holdings or an
/// amount term does not serialize — `write` refuses on validate, so the bytes
/// that would spell a standing or value mutation under kind 4 cannot exist.
#[test]
fn bond_post_endpoint_update_cannot_carry_holdings_or_a_term() {
    let base = BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x02; 32],
        kind: BondPostKind::EndpointUpdate {
            endpoint: [0x4E; 32],
        },
        holdings: Holdings::ShardSetCompact(Vec::new()),
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    };
    let refuse = |post: BondPost, why: &str| {
        let err = Input::BondPost(Box::new(post))
            .write(&mut Vec::new())
            .expect_err(why);
        assert!(
            err.to_string().contains("EndpointUpdate carries no"),
            "{why}: {err}"
        );
    };
    refuse(
        BondPost {
            holdings: Holdings::ShardSetCompact(vec![7]),
            ..base.clone()
        },
        "holdings list",
    );
    refuse(
        BondPost {
            holdings: Holdings::CompleteTree,
            ..base.clone()
        },
        "complete tree",
    );
    refuse(
        BondPost {
            bond_credit: 1,
            ..base.clone()
        },
        "credit",
    );
    refuse(
        BondPost {
            bond_debit: 1,
            ..base.clone()
        },
        "debit",
    );
    refuse(
        BondPost {
            bonded_total_atomic: 1,
            ..base
        },
        "bonded total",
    );
}

#[test]
fn bond_post_other_must_not_reuse_the_endpoint_update_tag() {
    // Other(4) would emit a blob that re-parses as EndpointUpdate, consuming
    // the holdings bytes as the endpoint. Refused at write, like Other(0).
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x02; 32],
        kind: BondPostKind::Other(4),
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 1,
        bond_credit: 1,
        bond_debit: 0,
    }));
    let err = input
        .write(&mut Vec::new())
        .expect_err("Other(4) must refuse");
    assert!(err.to_string().contains("coupled payload"), "{err}");
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
        p_canonical_id: [0x02; 32],
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
