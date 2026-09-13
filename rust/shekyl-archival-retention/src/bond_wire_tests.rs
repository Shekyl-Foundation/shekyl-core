// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::id::p_canonical_id_from_hybrid_pubkey;

fn join_market_vin(hybrid_pk: &[u8]) -> ArchivalBondPostVin {
    ArchivalBondPostVin::join_market(
        hybrid_pk.to_vec(),
        p_canonical_id_from_hybrid_pubkey(hybrid_pk).to_bytes(),
        vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
        [0xEE; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
        1_500_000_000,
        1_500_000_000,
    )
}

fn release_vin(hybrid_pk: &[u8]) -> ArchivalBondPostVin {
    ArchivalBondPostVin::release(
        hybrid_pk.to_vec(),
        p_canonical_id_from_hybrid_pubkey(hybrid_pk).to_bytes(),
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::empty(),
        },
        0,
        0,
        750_000_000,
    )
}

#[test]
fn bond_post_roundtrip_shard_set() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let vin = join_market_vin(&hybrid_pk);
    let wire = vin.serialize().unwrap();
    assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_BOND_POST);
    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    assert_eq!(decoded, vin);
}

#[test]
fn bond_post_complete_tree_has_no_shard_list_on_wire() {
    let hybrid_pk = vec![0x01; HYBRID_PUBKEY_CANONICAL_BYTES];
    let vin = ArchivalBondPostVin::join_market(
        hybrid_pk.clone(),
        p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
        vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
        [0xEE; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        750_000_000,
        750_000_000,
    );
    let wire = vin.serialize().unwrap();
    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    let holdings = decoded.holdings();
    assert_eq!(holdings.kind, HoldingsKind::CompleteTree);
    assert!(holdings.shard_ids.is_empty());
}

/// A truncated (or over-long) hybrid pubkey is malformed, not a shorter
/// valid key — both write and read demand the exact canonical length
/// (mirrors the emission wire; the C++ oracle enforces the same equality).
#[test]
fn bond_post_rejects_non_canonical_pubkey_length() {
    let mut vin = join_market_vin(&vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES]);
    vin.hybrid_public_key = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1];
    assert!(matches!(
        vin.serialize(),
        Err(WireError::HybridPubkeyLenNotCanonical { .. })
    ));
    vin.hybrid_public_key = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES + 1];
    assert!(matches!(
        vin.serialize(),
        Err(WireError::HybridPubkeyLenNotCanonical { .. })
    ));

    let mut wire = Vec::new();
    write_varint(&(HYBRID_PUBKEY_CANONICAL_BYTES - 1), &mut wire).unwrap();
    wire.extend_from_slice(&vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
    assert!(matches!(
        ArchivalBondPostVin::read_payload(&mut wire.as_slice()),
        Err(WireError::HybridPubkeyLenNotCanonical { .. })
    ));
}

/// §9.11: `bond_spend_pk` length is checked on JoinMarket; presence on any
/// other kind is unrepresentable (the payload variant does not carry the
/// field).
#[test]
fn bond_spend_pk_length_is_join_market_canonical() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let mut vin = join_market_vin(&hybrid_pk);
    vin.set_bond_spend_pk(vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
    assert!(matches!(
        vin.serialize(),
        Err(WireError::BondSpendPkLenNotCanonical { .. })
    ));
    vin.set_bond_spend_pk(Vec::new());
    assert!(matches!(
        vin.serialize(),
        Err(WireError::BondSpendPkLenNotCanonical { .. })
    ));

    let release = release_vin(&hybrid_pk);
    let wire = release.serialize().unwrap();
    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    assert_eq!(decoded, release);
    assert!(decoded.bond_spend_pk().is_none());
    assert!(decoded.endpoint().is_none());

    let mut wire = Vec::new();
    write_varint(&HYBRID_PUBKEY_CANONICAL_BYTES, &mut wire).unwrap();
    wire.extend_from_slice(&hybrid_pk);
    wire.extend_from_slice(&vin.p_canonical_id);
    wire.push(BondPostKind::JoinMarket as u8);
    write_varint(&(HYBRID_PUBKEY_CANONICAL_BYTES - 1), &mut wire).unwrap();
    wire.extend_from_slice(&vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
    assert!(matches!(
        ArchivalBondPostVin::read_payload(&mut wire.as_slice()),
        Err(WireError::BondSpendPkLenNotCanonical { .. })
    ));
}

/// Golden byte vector for the shared holdings codec.
///
/// **Blast radius: TWO consensus wires.** This fragment is byte-identical on
/// the bond-post wire (`0x03`, this module) **and** the reward-emission wire
/// (`0x04`, [`crate::emission_wire`], which mirrors this exact pin in
/// `emission_wire::tests::holdings_codec_golden_vector_shared_with_bond_wire`).
/// A change that moves these bytes is a consensus change to both surfaces and
/// must fail both suites loudly — do not "fix" this test by updating the pin
/// without a genesis-format decision covering both wires.
#[test]
fn holdings_codec_golden_vector_shared_with_emission_wire() {
    let shard_set = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    };
    assert_eq!(
        encode_holdings_descriptor(&shard_set).unwrap(),
        [0x00, 0x02, 0x07, 0x2A],
        "ShardSetCompact golden bytes moved — consensus change to BOTH wires"
    );
    let complete = HoldingsDescriptor {
        kind: HoldingsKind::CompleteTree,
        shard_ids: ShardSet::empty(),
    };
    assert_eq!(
        encode_holdings_descriptor(&complete).unwrap(),
        [0x01],
        "CompleteTree golden byte moved — consensus change to BOTH wires"
    );
    assert_eq!(
        read_holdings_descriptor(&mut [0x00u8, 0x02, 0x07, 0x2A].as_slice()).unwrap(),
        shard_set
    );
    assert_eq!(
        read_holdings_descriptor(&mut [0x01u8].as_slice()).unwrap(),
        complete
    );
}

#[test]
fn shard_set_rejects_oversize_at_construction() {
    let ids: Vec<u64> = (0..=MAX_HOLDINGS_SHARDS as u64).collect();
    assert_eq!(ids.len(), MAX_HOLDINGS_SHARDS + 1);
    assert_eq!(
        ShardSet::new(ids),
        Err(ShardSetError::CountExceeded {
            got: MAX_HOLDINGS_SHARDS + 1
        })
    );
    assert!(ShardSet::new((0..MAX_HOLDINGS_SHARDS as u64).collect()).is_ok());
}

#[test]
fn shard_set_rejects_duplicate_at_construction() {
    assert_eq!(
        ShardSet::new(vec![7, 42, 7]),
        Err(ShardSetError::Duplicate { shard_id: 7 })
    );
    assert!(ShardSet::new(vec![7, 42, 9]).is_ok());
    assert!(ShardSet::empty().is_empty());
}

#[test]
fn shard_set_preserves_insertion_order_byte_identically() {
    let unsorted = ShardSet::new(vec![42, 7]).unwrap();
    assert_eq!(unsorted.as_slice(), &[42, 7]);
    let holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: unsorted,
    };
    assert_eq!(
        encode_holdings_descriptor(&holdings).unwrap(),
        [0x00, 0x02, 0x2A, 0x07],
        "insertion order must survive encoding (no canonical sort)"
    );
    assert_eq!(
        read_holdings_descriptor(&mut [0x00u8, 0x02, 0x2A, 0x07].as_slice()).unwrap(),
        holdings
    );
}

#[test]
fn last_served_scan_is_exhaustive_on_holdings_kind() {
    assert_eq!(
        HoldingsKind::ShardSetCompact.last_served_scan(),
        LastServedScan::HeldShards
    );
    assert_eq!(
        HoldingsKind::CompleteTree.last_served_scan(),
        LastServedScan::AllShards
    );
    assert_ne!(
        LastServedScan::HeldShards as u8,
        LastServedScan::AllShards as u8
    );
}

#[test]
fn decode_rejects_duplicate_carrying_wire_bytes() {
    let dupe_bytes = [0x00u8, 0x02, 0x07, 0x07];
    assert!(matches!(
        read_holdings_descriptor(&mut dupe_bytes.as_slice()),
        Err(WireError::HoldingsDuplicateShard { shard_id: 7 })
    ));
    let mut oversize = vec![0x00u8];
    oversize.extend_from_slice(&[0x81, 0x20]);
    assert!(matches!(
        read_holdings_descriptor(&mut oversize.as_slice()),
        Err(WireError::HoldingsCountExceeded { got: 4097 })
    ));
}

/// The post-kind table ends at HoldingsUpdate (3). Byte 4 is an unknown
/// kind, not a reserved one: a bonded persona's endpoint never changes, so
/// no kind exists to rotate it (a new onion address is a new persona).
#[test]
fn post_kind_table_ends_at_holdings_update() {
    assert!(matches!(
        BondPostKind::from_u8(3),
        Ok(BondPostKind::HoldingsUpdate)
    ));
    assert!(matches!(
        BondPostKind::from_u8(4),
        Err(WireError::InvalidPostKind(4))
    ));
    assert!(matches!(
        BondPostKind::from_u8(5),
        Err(WireError::InvalidPostKind(5))
    ));
}
