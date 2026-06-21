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

use shekyl_wire::{BondPost, Holdings, Input, ServeCredit};

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
        post_kind: 0, // JoinMarket
        bond_spend_pk: Some(vec![0xCD; 1996]),
        holdings: Holdings {
            kind: 0, // ShardSetCompact
            shard_ids: vec![1, 2, 3, 9],
        },
        bonded_total_atomic: 750_000_000 * 4,
        bond_credit: 750_000_000 * 4,
        bond_debit: 0,
    }));
    let parsed = round_trip(&input);
    assert_eq!(parsed, input);
    // bond_spend_pk survived (the field the current impl omits).
    match parsed {
        Input::BondPost(bp) => assert!(bp.bond_spend_pk.is_some()),
        _ => panic!("expected BondPost"),
    }
}

#[test]
fn bond_post_non_joinmarket_has_no_bond_spend_pk() {
    // post_kind 3 = HoldingsUpdate: bond_spend_pk is absent on the wire.
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; 64],
        p_canonical_id: [0x02; 32],
        post_kind: 3,
        bond_spend_pk: None,
        holdings: Holdings {
            kind: 1, // CompleteTree — carries no shard list
            shard_ids: vec![],
        },
        bonded_total_atomic: 12_000_000_000,
        bond_credit: 9_000_000_000,
        bond_debit: 3_000_000_000,
    }));
    assert_eq!(round_trip(&input), input);
}

#[test]
fn joinmarket_bond_post_without_bond_spend_pk_is_an_error() {
    // Writing a JoinMarket post without bond_spend_pk must fail (it's required).
    let input = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; 64],
        p_canonical_id: [0x02; 32],
        post_kind: 0, // JoinMarket
        bond_spend_pk: None,
        holdings: Holdings {
            kind: 1,
            shard_ids: vec![],
        },
        bonded_total_atomic: 1,
        bond_credit: 1,
        bond_debit: 0,
    }));
    let mut bytes = Vec::new();
    let err = input
        .write(&mut bytes)
        .expect_err("JoinMarket requires bond_spend_pk");
    assert!(
        err.to_string().contains("bond_spend_pk"),
        "unexpected: {err}"
    );
}
