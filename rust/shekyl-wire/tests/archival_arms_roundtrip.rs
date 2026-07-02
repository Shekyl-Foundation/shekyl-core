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

use shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET;
use shekyl_wire::{BondPost, BondPostKind, Holdings, Input, ServeCredit};

fn round_trip(input: &Input) -> Input {
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write input arm");
    let mut cursor = &bytes[..];
    let parsed = Input::read(&mut cursor).expect("read input arm");
    assert!(cursor.is_empty(), "input arm left trailing bytes");
    parsed
}

#[test]
fn serve_credit_round_trips() {
    let input = Input::ServeCredit(Box::new(ServeCredit {
        p_canonical_id: [0x11; 32],
        shard_id: 7,
        settlement_epoch: 42,
        segment_subroot_rk: [0x22; 32],
        leaf_index_in_segment: 0x0403_0201,
        leaf_bytes: [0x33; 128],
        // bottom-to-top branch layers; widths/depths arbitrary but within bounds.
        c1_layers: vec![vec![[0x44; 32], [0x45; 32]], vec![[0x46; 32]]],
        c2_layers: vec![vec![[0x55; 32]]],
        hybrid_signature: vec![0x66; 3385],
    }));
    assert_eq!(round_trip(&input), input);
}

#[test]
fn bond_post_joinmarket_round_trips_with_bond_spend_pk() {
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xAB; 1996],
        p_canonical_id: [0x77; 32],
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xCD; 1996],
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
        hybrid_public_key: vec![0x01; 1996],
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
fn bond_post_other_must_not_reuse_joinmarket_tag() {
    // The JoinMarket coupling is now structural: `JoinMarket` always carries
    // bond_spend_pk (the old "JoinMarket without bond_spend_pk" state is now
    // unrepresentable — a compile-time guarantee, not a runtime check). The only
    // residual misuse — `Other` reusing the JoinMarket tag, which would emit a blob
    // that re-reads as a JoinMarket post — is rejected at write.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; 1996],
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
