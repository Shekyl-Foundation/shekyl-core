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

use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, HybridEd25519FnDsa};

use super::*;

/// An archive wide enough for every fixture shard.
const WIDTH: u64 = 16;

const EPOCH: SettlementEpoch = SettlementEpoch::from_raw(7);

/// Three personas' receipt keys, generated once, ordered as the personas
/// [`P1`], [`P2`], [`P3`].
fn keys() -> &'static [ReceiptSignPk; 3] {
    static KEYS: OnceLock<[ReceiptSignPk; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [1u8, 2, 3].map(|n| {
            HybridEd25519FnDsa::keypair_from_seeds(&[n; 32], &[n + 100; 32])
                .expect("keygen")
                .0
                .to_receipt_sign_pk()
        })
    })
}

const P1: PCanonicalId = PCanonicalId::from_bytes([0x10; 32]);
const P2: PCanonicalId = PCanonicalId::from_bytes([0x20; 32]);
const P3: PCanonicalId = PCanonicalId::from_bytes([0x30; 32]);

fn pair(persona: PCanonicalId, shard: u64) -> DrawablePair {
    DrawablePair {
        persona,
        shard: ShardId::from_raw(shard),
    }
}

fn all_keys() -> Vec<(PCanonicalId, &'static ReceiptSignPk)> {
    let k = keys();
    vec![(P1, &k[0]), (P2, &k[1]), (P3, &k[2])]
}

/// `key` with the byte at `at` replaced by `byte`: a string one edit away
/// from a key, as `ReceiptSignPk::as_bytes` says a fixture makes one.
fn edited(key: &ReceiptSignPk, at: usize, byte: u8) -> ReceiptSignPk {
    let mut bytes = *key.as_bytes();
    bytes[at] = byte;
    ReceiptSignPk::from_bytes(bytes)
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
    let drawable =
        DrawableEpoch::new(EPOCH, 512, all_keys(), supplied).expect("every pair has a key");
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
    let supplied_keys = vec![(P3, &k[2]), (P1, &k[0]), (P2, &k[1])];
    let drawable = DrawableEpoch::new(
        EPOCH,
        512,
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
        assert_eq!(&key.to_receipt_sign_pk(), *expected, "index {index}");
    }
}

/// A drawable epoch with a keyless pair cannot be built (`SCS-P19`). Red edit:
/// skip a pair whose persona has no key instead of failing; the drawable epoch
/// then builds with `D` one short and every later index names another
/// pair.
#[test]
fn a_pair_without_a_receipt_key_fails_construction() {
    let k = keys();
    let two_keys = vec![(P1, &k[0]), (P3, &k[2])];
    assert_eq!(
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            two_keys,
            [pair(P1, 2), pair(P2, 9), pair(P3, 1)]
        ),
        Err(DrawableEpochError::MissingReceiptKey {
            persona: P2,
            shard: ShardId::from_raw(9),
        })
    );
    // No keys at all.
    assert_eq!(
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            Vec::<(PCanonicalId, &ReceiptSignPk)>::new(),
            [pair(P1, 2)]
        ),
        Err(DrawableEpochError::MissingReceiptKey {
            persona: P1,
            shard: ShardId::from_raw(2),
        })
    );
}

/// A key that does not parse fails construction: the identity scheme's
/// header, and a key with one coefficient out of range. A key of the wrong
/// length is not among them: [`ReceiptSignPk`] is exactly 1,837 bytes, so
/// an empty or truncated key is not a value the constructor can be given.
/// Red edit: store the bytes and parse at use.
#[test]
fn a_receipt_key_that_does_not_parse_fails_construction() {
    let k = keys();
    let malformed = DrawableEpochError::ReceiptKeyMalformed { persona: P2 };
    let build = |bad: ReceiptSignPk| {
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            vec![(P1, k[0].clone()), (P2, bad)],
            [pair(P1, 2), pair(P2, 9)],
        )
    };
    assert_eq!(build(edited(&k[1], 1, 1)), Err(malformed));
    // The FN-DSA half starts after the 4-byte header, a 4-byte length, the
    // 32-byte Ed25519 key and a second 4-byte length. Sixteen one-bits
    // after its header byte set the first coefficient above q.
    let fn_dsa = 8 + 32 + 4;
    let out_of_range = edited(&edited(&k[1], fn_dsa + 1, 0xFF), fn_dsa + 2, 0xFF);
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
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            all_keys(),
            [pair(P1, 2), pair(P2, 9), pair(P1, 2)]
        ),
        Err(DrawableEpochError::DuplicatePair {
            persona: P1,
            shard: ShardId::from_raw(2),
        })
    );
    assert_eq!(
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            vec![(P1, &k[0]), (P2, &k[1]), (P1, &k[2])],
            [pair(P1, 2)],
        ),
        Err(DrawableEpochError::DuplicateReceiptKey { persona: P1 })
    );
}

/// An epoch with no drawable pair is a drawable epoch: `D` = 0. A key supplied
/// for a persona that holds no pair is not kept and is not parsed.
#[test]
fn an_epoch_with_no_pairs_is_an_empty_drawable_epoch() {
    let unparsable = ReceiptSignPk::from_bytes([0; shekyl_types::archival::RECEIPT_SIGN_PK_LEN]);
    let empty =
        DrawableEpoch::new(EPOCH, WIDTH, vec![(P1, unparsable)], []).expect("no pair to key");
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert_eq!(empty.pair(0), None);
    assert!(empty.receipt_key(0).is_none());
}

/// The digest vectors (`SO-D12` ruling B, widened by S1 of 2026-11-01),
/// computed independently of this crate from the encoding on
/// [`DrawableEpoch::digest`] with a standalone Keccak-f[1600] and SP 800-185
/// cSHAKE256 (checked against SHAKE256, NIST's cSHAKE256 sample 3, and the
/// four `-v1` vectors these replace), then pinned. Vectors 2 to 6 are at an
/// archive width of [`WIDTH`].
mod digest_vectors {
    use super::*;

    const E0: SettlementEpoch = SettlementEpoch::from_raw(0);
    const E5: SettlementEpoch = SettlementEpoch::from_raw(5);

    fn hex(digest: DrawableDigest) -> String {
        hex::encode(digest.as_bytes())
    }

    /// Vector 3's value: three pairs of one compact persona ([`P2`]) and
    /// one of another ([`P1`]). `p2_key` is [`P2`]'s receipt key.
    fn two_compact(p2_key: &ReceiptSignPk) -> DrawableEpoch {
        DrawableEpoch::new(
            E5,
            WIDTH,
            vec![(P1, &keys()[0]), (P2, p2_key)],
            [pair(P2, 0), pair(P2, 1), pair(P2, 2), pair(P1, 5)],
        )
        .expect("every pair has a key")
    }

    /// Vector 1: the empty set at epoch 0 over an empty archive, what
    /// genesis writes. Red edit: any change to the label, the epoch word,
    /// the width word or the empty lists' counts.
    #[test]
    fn the_empty_set_at_epoch_zero() {
        let empty = DrawableEpoch::empty(E0);
        assert_eq!(
            empty,
            DrawableEpoch::new(E0, 0, Vec::<(PCanonicalId, &ReceiptSignPk)>::new(), [])
                .expect("no pair to key")
        );
        assert_eq!(
            hex(empty.digest()),
            "5e8fe65de213f5b1703847916d229be2a6f51c33d7d521caf0c41553e9e1ad7a"
        );
    }

    /// Vector 2: one compact pair. Red edit: the shard's width or byte
    /// order, or the persona and key hashed in another order.
    #[test]
    fn one_compact_pair() {
        let one = DrawableEpoch::new(E5, WIDTH, vec![(P1, &keys()[0])], [pair(P1, 7)])
            .expect("the pair has a key");
        assert_eq!(
            hex(one.digest()),
            "b412c41d8b98f5d4a4701763b1a201968b414d77c775870296ad1c1d5c151878"
        );
    }

    /// Vector 3: three pairs of one persona and one of another, supplied
    /// out of canonical order. Red edit: hash the pairs as supplied, hash a
    /// key once per pair instead of once per persona, or drop a count.
    #[test]
    fn three_pairs_of_one_persona_and_one_of_another() {
        assert_eq!(
            hex(two_compact(&keys()[1]).digest()),
            "93538ea33901cee30fd288571137a175ee9ef0a28c02488a304ecd7bae9257cb"
        );
    }

    /// Vector 4: vector 3 with the last byte of one receipt key changed —
    /// an edit that still parses, so the value is built and only the key
    /// differs. The pairs are the same, so a digest over the pairs alone
    /// would give vector 3's. Red edit: leave the persona list out of the
    /// digest.
    #[test]
    fn one_byte_of_one_receipt_key_changes_the_digest() {
        let key = &keys()[1];
        let last = shekyl_types::archival::RECEIPT_SIGN_PK_LEN - 1;
        let changed = edited(key, last, key.as_bytes()[last] ^ 0x01);
        let digest = hex(two_compact(&changed).digest());
        assert_eq!(
            digest,
            "38f5036032170dd4418c4557e14a7b5cd6661ea11e36552ace5283ffc52e103b"
        );
        assert_ne!(digest, hex(two_compact(key).digest()));
    }

    /// Vector 5: vector 2 with one support member ([`P3`]). The pairs and
    /// their keys are vector 2's, so a digest that left the members out
    /// would give vector 2's. Red edit: leave the member list out.
    #[test]
    fn a_support_member_changes_the_digest() {
        let with_member = DrawableEpoch::new(E5, WIDTH, vec![(P1, &keys()[0])], [pair(P1, 7)])
            .and_then(|d| d.with_support(vec![(P3, &keys()[2])]))
            .expect("a member at a width above zero");
        assert_eq!(
            hex(with_member.digest()),
            "7925a3cd423bebf1e6e79028bad4691f716d837a2db43467e3db6313e0bdda3a"
        );
    }

    /// Vector 6: vector 2 at width 17. Nothing else differs. Red edit:
    /// leave the width word out.
    #[test]
    fn the_archive_width_changes_the_digest() {
        let wider = DrawableEpoch::new(E5, 17, vec![(P1, &keys()[0])], [pair(P1, 7)])
            .expect("the pair has a key");
        assert_eq!(
            hex(wider.digest()),
            "801e13f3208b7ff53f5cbc3e2f84bc4b348e391d4f857c1ef2d865964da636bd"
        );
    }
}

/// The support members are held in persona order with their own keys, and
/// a member holds no pair. Red edit: keep the members in the order supplied
/// (`support_members` then lists P3 first).
#[test]
fn support_members_are_held_in_persona_order_with_their_keys() {
    let k = keys();
    let drawable = DrawableEpoch::new(EPOCH, WIDTH, vec![(P2, &k[1])], [pair(P2, 3)])
        .and_then(|d| d.with_support(vec![(P3, &k[2]), (P1, &k[0])]))
        .expect("two members, one pair holder");
    let members: Vec<PCanonicalId> = drawable
        .support_members()
        .iter()
        .map(|(persona, _)| *persona)
        .collect();
    assert_eq!(members, [P1, P3]);
    assert_eq!(
        drawable
            .support_key(&P3)
            .map(FnDsaHybridPublicKey::to_receipt_sign_pk),
        Some(k[2].clone())
    );
    assert!(
        drawable.support_key(&P2).is_none(),
        "a pair holder is not a member"
    );
    assert_eq!(drawable.archive_width(), WIDTH);
    assert_eq!(drawable.len(), 1, "a member adds no pair");
}

/// The constructor refuses what the verifier must never meet. Red edits,
/// one per arm: drop the width check (a pair outside the archive is built);
/// drop the empty-archive check (a member of an empty archive is built);
/// drop the overlap check (a persona is both member and holder).
#[test]
fn a_snapshot_refuses_what_the_verifier_must_not_meet() {
    let k = keys();
    assert_eq!(
        DrawableEpoch::new(EPOCH, 3, vec![(P1, &k[0])], [pair(P1, 3)]),
        Err(DrawableEpochError::PairOutsideArchive {
            persona: P1,
            shard: ShardId::from_raw(3),
            width: 3,
        })
    );
    assert_eq!(
        DrawableEpoch::new(EPOCH, 0, Vec::<(PCanonicalId, &ReceiptSignPk)>::new(), [])
            .and_then(|d| d.with_support(vec![(P1, &k[0])])),
        Err(DrawableEpochError::SupportOnEmptyArchive)
    );
    assert_eq!(
        DrawableEpoch::new(EPOCH, WIDTH, vec![(P1, &k[0])], [pair(P1, 1)])
            .and_then(|d| d.with_support(vec![(P1, &k[0])])),
        Err(DrawableEpochError::SupportMemberHoldsPair { persona: P1 })
    );
    assert_eq!(
        DrawableEpoch::new(
            EPOCH,
            WIDTH,
            Vec::<(PCanonicalId, &ReceiptSignPk)>::new(),
            []
        )
        .and_then(|d| d.with_support(vec![(P1, &k[0]), (P1, &k[1])])),
        Err(DrawableEpochError::DuplicateSupportMember { persona: P1 })
    );
    let bad = edited(&k[0], 0, k[0].as_bytes()[0] ^ 0xFF);
    let refused = DrawableEpoch::new(
        EPOCH,
        WIDTH,
        Vec::<(PCanonicalId, &ReceiptSignPk)>::new(),
        [],
    )
    .and_then(|d| d.with_support(vec![(P1, bad)]));
    assert!(
        matches!(
            refused,
            Err(DrawableEpochError::SupportKeyMalformed { persona: P1 })
        ),
        "{refused:?}"
    );
    // No members at an empty archive is the empty snapshot.
    assert_eq!(
        DrawableEpoch::new(EPOCH, 0, Vec::<(PCanonicalId, &ReceiptSignPk)>::new(), [])
            .and_then(|d| d.with_support(Vec::<(PCanonicalId, &ReceiptSignPk)>::new())),
        Ok(DrawableEpoch::empty(EPOCH))
    );
}
