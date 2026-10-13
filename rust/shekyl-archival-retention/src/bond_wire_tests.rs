// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::id::p_canonical_id_from_hybrid_pubkey;

/// A receipt key's worth of fixture bytes. Not a key: nothing in this
/// module parses one (CEN-J28 does, in `shekyl-chain-rules`).
fn receipt_key() -> ReceiptSignPk {
    ReceiptSignPk::from_bytes([0x5C; RECEIPT_SIGN_PK_LEN])
}

fn join_market_vin(hybrid_pk: &[u8]) -> ArchivalBondPostVin {
    ArchivalBondPostVin::join_market(
        hybrid_pk.to_vec(),
        p_canonical_id_from_hybrid_pubkey(hybrid_pk).to_bytes(),
        vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
        receipt_key(),
        [0xEE; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
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
        receipt_key(),
        [0xEE; ENDPOINT_BYTES],
        HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        },
        750_000_000,
    );
    let wire = vin.serialize().unwrap();
    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    let holdings = decoded.holdings;
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

/// The post-kind table is Reinstate (1), Release (2) and JoinMarket (5).
/// Byte 3 was HoldingsUpdate — REJECTED 2026-09-20 (immutable-bond); it is
/// an unknown kind, not a reserved one, so it cannot be silently re-minted.
/// Byte 4 is the same class: a bonded persona's endpoint never changes, so
/// no kind exists to rotate it (a new onion address is a new persona).
///
/// *Moved 2026-10-12 (ruling on PR #1046):* this test was
/// `post_kind_table_ends_at_release_and_rejects_the_deleted_holdings_update_byte`.
/// The table no longer ends at Release — the JoinMarket's byte is 5 — and
/// the three assertions it made are kept as they were.
#[test]
fn post_kind_table_has_release_at_2_and_rejects_the_deleted_bytes_3_and_4() {
    assert!(matches!(
        BondPostKind::from_u8(2),
        Ok(BondPostKind::Release)
    ));
    assert!(matches!(
        BondPostKind::from_u8(3),
        Err(WireError::InvalidPostKind(3))
    ));
    assert!(matches!(
        BondPostKind::from_u8(4),
        Err(WireError::InvalidPostKind(4))
    ));
}

/// Byte 0 was the keyless JoinMarket. RETIRED 2026-10-12 (ruling on PR
/// #1046): the receipt key is mandatory — a keyless join would put a pair
/// in the drawable set that the `h_open(E)` snapshot cannot build — so the
/// byte joins 3 and 4: unassigned, refused, never re-minted. Byte 5 is the
/// JoinMarket, the one JoinMarket byte, and 6 is the first past the table.
#[test]
fn byte_0_is_the_retired_keyless_join_market_and_byte_5_is_the_join_market() {
    assert!(matches!(
        BondPostKind::from_u8(0),
        Err(WireError::InvalidPostKind(0))
    ));
    let kind = BondPostKind::from_u8(5).expect("byte 5 is the JoinMarket");
    assert_eq!(kind, BondPostKind::JoinMarket);
    assert_eq!(kind as u8, 5);
    assert!(kind.is_join_market());
    assert!(kind.unit_kind().is_none());
    assert!(!BondPostKind::Reinstate.is_join_market());
    assert!(!BondPostKind::Release.is_join_market());
    assert!(matches!(
        BondPostKind::from_u8(6),
        Err(WireError::InvalidPostKind(6))
    ));
    for byte in 0..=u8::MAX {
        assert_eq!(
            BondPostKind::from_u8(byte).is_ok(),
            matches!(byte, 1 | 2 | 5),
            "byte {byte}"
        );
    }
}

/// A JoinMarket's bytes, field by field: tag, identity key, hint, kind 5,
/// `varint ‖ bond_spend_pk`, `varint(1837) ‖ receipt_sign_pk`, endpoint,
/// then holdings and amounts. The receipt key sits between `bond_spend_pk`
/// and the endpoint and reads back as the value written.
#[test]
fn a_join_market_carries_its_receipt_key_between_bond_spend_pk_and_the_endpoint() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let vin = join_market_vin(&hybrid_pk);
    assert_eq!(vin.post_kind(), BondPostKind::JoinMarket);
    assert!(vin.post_kind().is_join_market());
    assert_eq!(vin.receipt_sign_pk(), Some(&receipt_key()));
    assert_eq!(release_vin(&hybrid_pk).receipt_sign_pk(), None);
    assert!(!release_vin(&hybrid_pk).post_kind().is_join_market());

    let wire = vin.serialize().unwrap();
    let kind_at = 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES + 32;
    assert_eq!(wire[kind_at], 5);
    let receipt_prefix_at = kind_at + 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES;
    let mut prefix = Vec::new();
    write_varint(&RECEIPT_SIGN_PK_LEN, &mut prefix).unwrap();
    assert_eq!(prefix.len(), 2);
    assert_eq!(&wire[receipt_prefix_at..receipt_prefix_at + 2], &prefix[..]);
    let key_at = receipt_prefix_at + 2;
    assert_eq!(
        &wire[key_at..key_at + RECEIPT_SIGN_PK_LEN],
        &receipt_key().as_bytes()[..]
    );
    let endpoint_at = key_at + RECEIPT_SIGN_PK_LEN;
    assert_eq!(
        &wire[endpoint_at..endpoint_at + ENDPOINT_BYTES],
        &[0xEE; ENDPOINT_BYTES]
    );

    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    assert_eq!(decoded, vin);
    let exact = ArchivalBondPostVin::read_payload_exact(&mut &wire[1..]).unwrap();
    assert_eq!(exact, vin);
}

/// The reader refuses a receipt key whose prefix declares any length but
/// 1,837, at the prefix, and refuses the JoinMarket's own bytes under the
/// retired kind byte 0.
#[test]
fn a_receipt_key_prefix_is_canonical_or_refused_and_kind_0_does_not_parse() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let good = join_market_vin(&hybrid_pk).serialize().unwrap();
    let kind_at = 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES + 32;
    let prefix_at = kind_at + 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES;
    for len in [RECEIPT_SIGN_PK_LEN - 1, RECEIPT_SIGN_PK_LEN + 1] {
        let mut prefix = Vec::new();
        write_varint(&len, &mut prefix).unwrap();
        assert_eq!(prefix.len(), 2);
        let mut bad = good.clone();
        bad[prefix_at..prefix_at + 2].copy_from_slice(&prefix);
        assert!(
            matches!(
                ArchivalBondPostVin::read(&mut bad.as_slice()),
                Err(WireError::ReceiptSignPkLenNotCanonical { got }) if got == len
            ),
            "len {len}"
        );
    }
    let mut retired = good.clone();
    retired[kind_at] = 0;
    assert!(matches!(
        ArchivalBondPostVin::read(&mut retired.as_slice()),
        Err(WireError::InvalidPostKind(0))
    ));
}
