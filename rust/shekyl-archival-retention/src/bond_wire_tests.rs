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

/// The post-kind table ends at Release (2). Byte 3 was HoldingsUpdate —
/// REJECTED 2026-09-20 (immutable-bond); it is an unknown kind, not a
/// reserved one, so it cannot be silently re-minted. Byte 4 is the same
/// class: a bonded persona's endpoint never changes, so no kind exists to
/// rotate it (a new onion address is a new persona).
#[test]
fn post_kind_table_ends_at_release_and_rejects_the_deleted_holdings_update_byte() {
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

// ---- the JoinMarket that carries a receipt key (kind 5) --------------------

fn receipt_join_market_vin(hybrid_pk: &[u8], receipt_sign_pk: Vec<u8>) -> ArchivalBondPostVin {
    let mut vin = join_market_vin(hybrid_pk);
    match &mut vin.kind {
        BondKind::JoinMarket {
            receipt_sign_pk: slot,
            ..
        } => *slot = Some(receipt_sign_pk),
        _ => panic!("join_market_vin builds a JoinMarket"),
    }
    vin
}

/// Byte 5 is the JoinMarket that carries a receipt key: a JoinMarket to
/// every predicate, and not a unit kind. Bytes 3 and 4 stay what
/// `post_kind_table_ends_at_release_and_rejects_the_deleted_holdings_update_byte`
/// pins them as; 6 is the first byte past the table.
#[test]
fn byte_5_is_the_receipt_join_market_and_is_a_join_market() {
    let kind = BondPostKind::from_u8(5).expect("byte 5 is assigned");
    assert_eq!(kind, BondPostKind::JoinMarketReceipt);
    assert_eq!(kind as u8, 5);
    assert!(kind.is_join_market());
    assert!(BondPostKind::JoinMarket.is_join_market());
    assert!(!BondPostKind::Reinstate.is_join_market());
    assert!(!BondPostKind::Release.is_join_market());
    assert!(kind.unit_kind().is_none());
    assert!(matches!(
        BondPostKind::from_u8(6),
        Err(WireError::InvalidPostKind(6))
    ));
}

/// The tag is the key's presence: the same JoinMarket is kind 0 without a
/// receipt key and kind 5 with one, and the accessor reads back what was set.
#[test]
fn a_join_market_s_tag_is_its_receipt_key_s_presence() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let keyless = join_market_vin(&hybrid_pk);
    assert_eq!(keyless.post_kind(), BondPostKind::JoinMarket);
    assert_eq!(keyless.receipt_sign_pk(), None);
    assert!(keyless.kind.is_join_market());

    let key = vec![0x5C; RECEIPT_SIGN_PK_CANONICAL_BYTES];
    let keyed = receipt_join_market_vin(&hybrid_pk, key.clone());
    assert_eq!(keyed.post_kind(), BondPostKind::JoinMarketReceipt);
    assert_eq!(keyed.receipt_sign_pk(), Some(&key[..]));
    assert!(keyed.kind.is_join_market());
    assert_eq!(keyed.bond_spend_pk(), keyless.bond_spend_pk());
    assert_eq!(keyed.endpoint(), keyless.endpoint());

    assert_eq!(release_vin(&hybrid_pk).receipt_sign_pk(), None);
    assert!(!release_vin(&hybrid_pk).kind.is_join_market());
}

/// Kind 5 round-trips, and its bytes are kind 0's with the kind byte moved
/// and the length-prefixed key spliced in before the endpoint: nothing else
/// about the post's encoding differs.
#[test]
fn a_receipt_join_market_round_trips_and_is_kind_0_plus_the_key() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let key = vec![0x5C; RECEIPT_SIGN_PK_CANONICAL_BYTES];
    let keyless = join_market_vin(&hybrid_pk).serialize().unwrap();
    let vin = receipt_join_market_vin(&hybrid_pk, key.clone());
    let wire = vin.serialize().unwrap();

    let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
    assert_eq!(decoded, vin);
    assert_eq!(decoded.receipt_sign_pk(), Some(&key[..]));
    let exact = ArchivalBondPostVin::read_payload_exact(&mut &wire[1..]).unwrap();
    assert_eq!(exact, vin);

    // tag ‖ varint(1996) ‖ identity ‖ hint, then the kind byte.
    let kind_at = 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES + 32;
    assert_eq!(keyless[kind_at], BondPostKind::JoinMarket as u8);
    assert_eq!(wire[kind_at], BondPostKind::JoinMarketReceipt as u8);
    // The kind byte, then varint(1996) ‖ bond_spend_pk, then the splice.
    let splice_at = kind_at + 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES;
    let mut expected = keyless.clone();
    expected[kind_at] = 5;
    let mut spliced = Vec::new();
    write_varint(&RECEIPT_SIGN_PK_CANONICAL_BYTES, &mut spliced).unwrap();
    spliced.extend_from_slice(&key);
    expected.splice(splice_at..splice_at, spliced);
    assert_eq!(wire, expected);
}

/// A receipt key of the wrong length is refused by name at the writer and at
/// the reader, like `bond_spend_pk`.
#[test]
fn receipt_sign_pk_length_is_canonical_or_refused() {
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    for len in [
        0,
        RECEIPT_SIGN_PK_CANONICAL_BYTES - 1,
        RECEIPT_SIGN_PK_CANONICAL_BYTES + 1,
        HYBRID_PUBKEY_CANONICAL_BYTES,
    ] {
        let vin = receipt_join_market_vin(&hybrid_pk, vec![0x5C; len]);
        assert!(
            matches!(
                vin.serialize(),
                Err(WireError::ReceiptSignPkLenNotCanonical { got }) if got == len
            ),
            "write, len {len}"
        );
    }

    // On the wire: a canonical post whose receipt-key prefix declares one
    // byte fewer. The reader refuses at the prefix, before reading the key.
    let good = receipt_join_market_vin(&hybrid_pk, vec![0x5C; RECEIPT_SIGN_PK_CANONICAL_BYTES])
        .serialize()
        .unwrap();
    let prefix_at =
        1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES + 32 + 1 + 2 + HYBRID_PUBKEY_CANONICAL_BYTES;
    let mut canonical_prefix = Vec::new();
    write_varint(&RECEIPT_SIGN_PK_CANONICAL_BYTES, &mut canonical_prefix).unwrap();
    assert_eq!(
        &good[prefix_at..prefix_at + canonical_prefix.len()],
        &canonical_prefix[..]
    );
    let mut short_prefix = Vec::new();
    write_varint(&(RECEIPT_SIGN_PK_CANONICAL_BYTES - 1), &mut short_prefix).unwrap();
    assert_eq!(short_prefix.len(), canonical_prefix.len());
    let mut bad = good.clone();
    bad[prefix_at..prefix_at + short_prefix.len()].copy_from_slice(&short_prefix);
    assert!(matches!(
        ArchivalBondPostVin::read(&mut bad.as_slice()),
        Err(WireError::ReceiptSignPkLenNotCanonical { got })
            if got == RECEIPT_SIGN_PK_CANONICAL_BYTES - 1
    ));
}

/// The semantic verify reads a kind-5 JoinMarket exactly as it reads a
/// kind-0 one: same floor, same endpoint rule, same record-exists refusal.
#[test]
fn verify_join_market_treats_the_receipt_form_as_a_join_market() {
    use crate::bond_post::{verify_join_market_bond_post, BondPostError};
    let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
    let keyless = join_market_vin(&hybrid_pk);
    let keyed = receipt_join_market_vin(&hybrid_pk, vec![0x5C; RECEIPT_SIGN_PK_CANONICAL_BYTES]);
    assert_eq!(verify_join_market_bond_post(&keyless, false), Ok(()));
    assert_eq!(verify_join_market_bond_post(&keyed, false), Ok(()));
    assert_eq!(
        verify_join_market_bond_post(&keyed, true),
        Err(BondPostError::RecordExists)
    );
    let mut zero_endpoint = keyed.clone();
    zero_endpoint.set_endpoint([0; ENDPOINT_BYTES]);
    assert_eq!(
        verify_join_market_bond_post(&zero_endpoint, false),
        Err(BondPostError::EndpointZero)
    );
    let mut off_floor = keyed;
    off_floor.bond_credit += 1;
    assert_eq!(
        verify_join_market_bond_post(&off_floor, false),
        Err(BondPostError::FloorMismatch)
    );
}
