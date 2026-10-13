// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `h_open(E)` drawable epoch's constructor: what it refuses, the order it
//! keeps, and that a key is read by the pair's persona. Real scheme-3
//! keys throughout — the constructor parses them.
//!
//! Each test names the edit that turns it red (rule 50).

use std::sync::OnceLock;

use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;

use super::*;

const EPOCH: SettlementEpoch = SettlementEpoch::from_raw(7);

/// Three personas' receipt keys, generated once: canonical bytes, ordered
/// as the personas `[0x10; 32]`, `[0x20; 32]`, `[0x30; 32]`.
fn keys() -> &'static [Vec<u8>; 3] {
    static KEYS: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [1u8, 2, 3].map(|n| {
            HybridEd25519FnDsa::keypair_from_seeds(&[n; 32], &[n + 100; 32])
                .expect("keygen")
                .0
                .to_canonical_bytes()
        })
    })
}

const P1: [u8; 32] = [0x10; 32];
const P2: [u8; 32] = [0x20; 32];
const P3: [u8; 32] = [0x30; 32];

fn pair(p_id: [u8; 32], shard_id: u64) -> DrawablePair {
    DrawablePair { p_id, shard_id }
}

fn all_keys() -> Vec<([u8; 32], Vec<u8>)> {
    let k = keys();
    vec![(P1, k[0].clone()), (P2, k[1].clone()), (P3, k[2].clone())]
}

/// Canonical order is persona id bytes, then shard id numerically — not
/// the order supplied, and not the shard id's little-endian bytes. Red
/// edit: drop the sort in `DrawableEpoch::new`; or sort shards by their
/// LE bytes, which puts 256 (`00 01 …`) before 2 (`02 00 …`).
#[test]
fn pairs_are_held_in_canonical_order() {
    let supplied = [
        pair(P3, 1),
        pair(P1, 256),
        pair(P2, 9),
        pair(P1, 2),
        pair(P2, 0),
        pair(P1, 300),
    ];
    let drawable = DrawableEpoch::new(EPOCH, all_keys(), supplied).expect("every pair has a key");
    assert_eq!(drawable.epoch(), EPOCH);
    assert_eq!(drawable.len(), 6);
    assert!(!drawable.is_empty());
    let held: Vec<DrawablePair> = (0..6)
        .map(|i| drawable.pair(i).expect("below len"))
        .collect();
    assert_eq!(
        held,
        [
            pair(P1, 2),
            pair(P1, 256),
            pair(P1, 300),
            pair(P2, 0),
            pair(P2, 9),
            pair(P3, 1),
        ]
    );
    assert_eq!(drawable.pair(6), None);
    assert_eq!(drawable.pair(u64::MAX), None);
    assert!(drawable.receipt_key(6).is_none());
}

/// Each pair's key is its own persona's, whichever shard it is and
/// wherever the key sat in the input. Red edit: index the keys by the
/// pair's position instead of by its persona — index 1 would read the
/// second persona's key for the first persona's second shard.
#[test]
fn a_pairs_receipt_key_is_its_personas() {
    let k = keys();
    // Keys supplied in an order that is not the personas' order.
    let supplied_keys = vec![(P3, k[2].clone()), (P1, k[0].clone()), (P2, k[1].clone())];
    let drawable = DrawableEpoch::new(
        EPOCH,
        supplied_keys,
        [
            pair(P1, 2),
            pair(P1, 256),
            pair(P2, 0),
            pair(P3, 1),
            pair(P3, 4),
        ],
    )
    .expect("every pair has a key");
    let expect = [&k[0], &k[0], &k[1], &k[2], &k[2]];
    for (index, expected) in expect.iter().enumerate() {
        let key = drawable
            .receipt_key(index as u64)
            .expect("a pair in D has a key");
        assert_eq!(&key.to_canonical_bytes(), *expected, "index {index}");
    }
}

/// A drawable epoch with a keyless pair cannot be built (`SCS-P19`). Red edit:
/// skip a pair whose persona has no key instead of failing; the drawable epoch
/// then builds with `D` one short and every later index names another
/// pair.
#[test]
fn a_pair_without_a_receipt_key_fails_construction() {
    let k = keys();
    let two_keys = vec![(P1, k[0].clone()), (P3, k[2].clone())];
    assert_eq!(
        DrawableEpoch::new(EPOCH, two_keys, [pair(P1, 2), pair(P2, 9), pair(P3, 1)]),
        Err(DrawableEpochError::MissingReceiptKey {
            persona: PCanonicalId::from_bytes(P2),
            shard_id: 9,
        })
    );
    // No keys at all.
    assert_eq!(
        DrawableEpoch::new(EPOCH, Vec::<([u8; 32], Vec<u8>)>::new(), [pair(P1, 2)]),
        Err(DrawableEpochError::MissingReceiptKey {
            persona: PCanonicalId::from_bytes(P1),
            shard_id: 2,
        })
    );
}

/// A key that does not parse fails construction: empty, truncated, the
/// identity scheme's header, and a key with one coefficient out of range.
/// Red edit: store the bytes and parse at use.
#[test]
fn a_receipt_key_that_does_not_parse_fails_construction() {
    let k = keys();
    let malformed = DrawableEpochError::ReceiptKeyMalformed {
        persona: PCanonicalId::from_bytes(P2),
    };
    let build = |bad: Vec<u8>| {
        DrawableEpoch::new(
            EPOCH,
            vec![(P1, k[0].clone()), (P2, bad)],
            [pair(P1, 2), pair(P2, 9)],
        )
    };
    assert_eq!(build(Vec::new()), Err(malformed));
    assert_eq!(build(k[1][..k[1].len() - 1].to_vec()), Err(malformed));
    let mut wrong_scheme = k[1].clone();
    wrong_scheme[1] = 1;
    assert_eq!(build(wrong_scheme), Err(malformed));
    // The FN-DSA half starts after the 4-byte header, a 4-byte length, the
    // 32-byte Ed25519 key and a second 4-byte length. Sixteen one-bits
    // after its header byte set the first coefficient above q.
    let mut out_of_range = k[1].clone();
    out_of_range[8 + 32 + 4 + 1] = 0xFF;
    out_of_range[8 + 32 + 4 + 2] = 0xFF;
    assert_eq!(build(out_of_range), Err(malformed));
    // The control: the same call with the key intact builds.
    assert!(build(k[1].clone()).is_ok());
}

/// Duplicates are refused, pairs and keys both. Red edit: `dedup` instead
/// of refusing — a doubled pair would silently shift no index, but a
/// doubled key with different bytes would make the kept one a matter of
/// sort stability.
#[test]
fn duplicates_are_refused() {
    let k = keys();
    assert_eq!(
        DrawableEpoch::new(EPOCH, all_keys(), [pair(P1, 2), pair(P2, 9), pair(P1, 2)]),
        Err(DrawableEpochError::DuplicatePair {
            persona: PCanonicalId::from_bytes(P1),
            shard_id: 2,
        })
    );
    assert_eq!(
        DrawableEpoch::new(
            EPOCH,
            vec![(P1, k[0].clone()), (P2, k[1].clone()), (P1, k[2].clone())],
            [pair(P1, 2)],
        ),
        Err(DrawableEpochError::DuplicateReceiptKey {
            persona: PCanonicalId::from_bytes(P1),
        })
    );
}

/// An epoch with no drawable pair is a drawable epoch: `D` = 0. A key supplied
/// for a persona that holds no pair is not kept and is not parsed.
#[test]
fn an_epoch_with_no_pairs_is_an_empty_drawable_epoch() {
    let empty = DrawableEpoch::new(EPOCH, vec![(P1, vec![0u8; 3])], []).expect("no pair to key");
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert_eq!(empty.pair(0), None);
    assert!(empty.receipt_key(0).is_none());
}
