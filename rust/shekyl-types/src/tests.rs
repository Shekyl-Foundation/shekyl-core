// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the foundational domain newtypes: transparency (wire
//! identity to the wrapped primitive), the height/count algebra, and the
//! hex hash formatting.

extern crate std;

use std::prelude::v1::*;

use super::*;

#[test]
fn edge_round_trip() {
    assert_eq!(BlockHeight::from_raw(42).to_raw(), 42);
    assert_eq!(GlobalOutputIndex::from_raw(7).to_raw(), 7);
    assert_eq!(PSlot::from_raw(3).to_raw(), 3);
    assert_eq!(PSlot::from_raw(3).index(), 3);
    assert!(BlockHeight::ZERO.is_zero());
    assert!(!BlockCount::from_raw(1).is_zero());

    let bytes = [3u8; 32];
    assert_eq!(TxHash::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(BlockHash::from_bytes(bytes).as_bytes(), &bytes);
    assert_eq!(ShardId::from_raw(9).to_raw(), 9);
    assert_eq!(LeafIndex::from_raw(4).to_raw(), 4);
    assert_eq!(BlockWeight::from_raw(1_000).to_raw(), 1_000);
    assert_eq!(LongTermWeight::from_raw(800).to_raw(), 800);
    assert_eq!(PqcAuthHash::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(PrefixHash::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(AttestationRoot::from_bytes(bytes).as_bytes(), &bytes);
    assert_eq!(OneTimePubkey::from_bytes(bytes).to_bytes(), bytes);
    fn via_trait<T: Hash32Bytes>(bytes: [u8; 32]) -> [u8; 32] {
        T::from_bytes(bytes).to_bytes()
    }
    assert_eq!(via_trait::<PrefixHash>(bytes), bytes);
    assert_eq!(via_trait::<CurveTreeRoot>(bytes), bytes);
    assert_eq!(CommitmentBytes::from_bytes(bytes).to_bytes(), bytes);
}

#[test]
fn serde_is_transparent_to_inner_u64() {
    // `#[serde(transparent)]` means the postcard wire bytes of the newtype
    // are byte-identical to the bare `u64`. A type-name change in a persisted
    // field still bumps the owning block's version (rule 42).
    let typed = postcard::to_allocvec(&BlockHeight::from_raw(0x0102_0304)).unwrap();
    let raw = postcard::to_allocvec(&0x0102_0304u64).unwrap();
    assert_eq!(typed, raw);

    let back: BlockHeight = postcard::from_bytes(&raw).unwrap();
    assert_eq!(back, BlockHeight::from_raw(0x0102_0304));
}

#[test]
fn serde_is_transparent_to_inner_bytes() {
    let bytes = [0xABu8; 32];
    let typed = postcard::to_allocvec(&TxHash::from_bytes(bytes)).unwrap();
    let raw = postcard::to_allocvec(&bytes).unwrap();
    assert_eq!(typed, raw);

    let back: TxHash = postcard::from_bytes(&raw).unwrap();
    assert_eq!(back, TxHash::from_bytes(bytes));
}

#[test]
fn invoice_unix_floor_refuses_height_shaped_seconds() {
    assert!(Timestamp::from_invoice_unix(999_999_999).is_none());
    assert_eq!(
        Timestamp::from_invoice_unix(Timestamp::INVOICE_UNIX_FLOOR),
        Some(Timestamp::from_raw(Timestamp::INVOICE_UNIX_FLOOR))
    );
}

#[test]
fn height_plus_count_is_height() {
    let h = BlockHeight::from_raw(100);
    let span = BlockCount::from_raw(10);
    assert_eq!(h + span, BlockHeight::from_raw(110));
    assert_eq!(h - span, BlockHeight::from_raw(90));
}

#[test]
fn height_minus_height_is_count() {
    let later = BlockHeight::from_raw(150);
    let earlier = BlockHeight::from_raw(40);
    assert_eq!(later - earlier, BlockCount::from_raw(110));
}

#[test]
fn count_plus_count_is_count() {
    assert_eq!(
        BlockCount::from_raw(3) + BlockCount::from_raw(4),
        BlockCount::from_raw(7)
    );
}

#[test]
fn checked_and_saturating_boundaries() {
    let h = BlockHeight::from_raw(5);
    assert_eq!(
        h.checked_add(BlockCount::from_raw(2)),
        Some(BlockHeight::from_raw(7))
    );
    assert_eq!(
        BlockHeight::from_raw(u64::MAX).checked_add(BlockCount::from_raw(1)),
        None
    );

    let later = BlockHeight::from_raw(10);
    let earlier = BlockHeight::from_raw(3);
    assert_eq!(later.checked_sub(earlier), Some(BlockCount::from_raw(7)));
    // `earlier` ahead of `self` → None (checked) / ZERO (saturating).
    assert_eq!(earlier.checked_sub(later), None);
    assert_eq!(earlier.saturating_sub(later), BlockCount::ZERO);
    assert_eq!(
        BlockHeight::from_raw(0).saturating_sub_count(BlockCount::ONE),
        BlockHeight::ZERO
    );
    assert_eq!(
        BlockHeight::from_raw(5).saturating_sub_count(BlockCount::ONE),
        BlockHeight::from_raw(4)
    );
    assert_eq!(
        BlockHeight::from_raw(5).checked_add(BlockCount::ONE),
        Some(BlockHeight::from_raw(6))
    );
    assert_eq!(
        BlockHeight::from_raw(5).saturating_add(BlockCount::from_raw(2)),
        BlockHeight::from_raw(7)
    );
    assert_eq!(
        BlockHeight::from_raw(u64::MAX).saturating_add(BlockCount::ONE),
        BlockHeight::from_raw(u64::MAX)
    );
    assert_eq!(BlockHeight::ZERO.checked_sub_count(BlockCount::ONE), None);
}

#[test]
#[should_panic(expected = "underflowed (rhs ahead of self)")]
fn height_subtraction_underflow_panics() {
    let _ = BlockHeight::from_raw(3) - BlockHeight::from_raw(10);
}

#[test]
fn timestamp_secs_since() {
    let now = Timestamp::from_raw(1_000);
    let before = Timestamp::from_raw(600);
    assert_eq!(now.checked_secs_since(before), Some(400));
    assert_eq!(before.checked_secs_since(now), None);
    assert_eq!(now.checked_add_secs(50), Some(Timestamp::from_raw(1_050)));
    assert_eq!(Timestamp::from_raw(u64::MAX).checked_add_secs(1), None);
}

/// The two chain facts a [`ChainCount`] carries: the tip is one below the
/// count (`None` on an empty chain — no laundering a count into a height),
/// and the next block's height is numerically the count itself.
#[test]
fn chain_count_bridges() {
    let count = ChainCount::from_raw(30_001);
    assert_eq!(count.tip(), Some(BlockHeight::from_raw(30_000)));
    assert_eq!(count.next_height(), BlockHeight::from_raw(30_001));

    let empty = ChainCount::ZERO;
    assert_eq!(empty.tip(), None, "an empty chain has no tip");
    assert_eq!(
        empty.next_height(),
        BlockHeight::from_raw(0),
        "the next block of an empty chain is genesis"
    );

    // `from_next_height` is C6's inverse, not "this existing block as a count".
    assert_eq!(ChainCount::from_next_height(count.next_height()), count);
    assert_eq!(ChainCount::from_next_height(empty.next_height()), empty);

    assert!(count.has_block(BlockHeight::from_raw(30_000)));
    assert!(count.has_block(BlockHeight::ZERO));
    assert!(!count.has_block(count.next_height()));
    assert!(!empty.has_block(BlockHeight::ZERO));
}

#[test]
fn chain_count_plus_span_is_count() {
    let count = ChainCount::from_raw(100);
    let span = BlockCount::from_raw(10);
    assert_eq!(count + span, ChainCount::from_raw(110));
    assert_eq!(count - span, ChainCount::from_raw(90));
    assert_eq!(count.saturating_add(span), ChainCount::from_raw(110));
    assert_eq!(count.saturating_sub_count(span), ChainCount::from_raw(90));
}

#[test]
fn chain_count_minus_count_is_span() {
    let later = ChainCount::from_raw(150);
    let earlier = ChainCount::from_raw(40);
    assert_eq!(later - earlier, BlockCount::from_raw(110));
    assert_eq!(later.checked_sub(earlier), Some(BlockCount::from_raw(110)));
    assert_eq!(earlier.checked_sub(later), None);
    assert_eq!(earlier.saturating_sub(later), BlockCount::ZERO);
}

#[test]
fn chain_count_saturating_and_checked_boundaries() {
    assert_eq!(
        ChainCount::from_raw(5).checked_add(BlockCount::from_raw(2)),
        Some(ChainCount::from_raw(7))
    );
    assert_eq!(
        ChainCount::from_raw(u64::MAX).checked_add(BlockCount::from_raw(1)),
        None
    );
    assert_eq!(
        ChainCount::ZERO.saturating_sub_count(BlockCount::ONE),
        ChainCount::ZERO
    );
    assert_eq!(ChainCount::ZERO.checked_sub_count(BlockCount::ONE), None);
    assert_eq!(
        ChainCount::from_raw(u64::MAX).saturating_add(BlockCount::ONE),
        ChainCount::from_raw(u64::MAX)
    );
    // Exclusive-end split used by the pscan horizon: count − depth, then
    // next_height is the exclusive ordinal bound (COUNT=100, depth=10 → 90).
    let claimed = ChainCount::from_raw(100);
    let horizon = claimed
        .saturating_sub_count(BlockCount::from_raw(10))
        .next_height();
    assert_eq!(horizon, BlockHeight::from_raw(90));
    // Corroboration min: exclusive scan end as count, plus the reorg span.
    let scanned = ChainCount::from_next_height(horizon);
    assert_eq!(
        scanned.saturating_add(BlockCount::from_raw(10)),
        ChainCount::from_raw(100)
    );
}

#[test]
#[should_panic(expected = "underflowed below empty")]
fn chain_count_subtraction_underflow_panics() {
    let _ = ChainCount::from_raw(3) - BlockCount::from_raw(10);
}

#[test]
fn hash_display_is_lowercase_hex() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xDE;
    bytes[1] = 0xAD;
    bytes[31] = 0x01;
    let shown = TxHash::from_bytes(bytes).to_string();
    assert_eq!(shown.len(), 64);
    assert!(shown.starts_with("dead"));
    assert!(shown.ends_with("01"));
    // Debug delegates to the hex form, wrapped in the type name.
    assert_eq!(
        format!("{:?}", TxHash::from_bytes(bytes)),
        format!("TxHash({shown})")
    );
}

#[test]
fn pcanonical_id_debug_is_truncated_but_display_is_full() {
    // `PCanonicalId` is the persona identity: the *full* id in a local log or
    // panic backtrace is a `P`↔principal correlation artifact (the firewall edge),
    // so its `Debug` is truncated to the first two bytes. `Display` stays the full
    // hex encoding. (This replaces the safety property the deleted local
    // `PCircuitTag::Debug` used to carry, now on the type itself.)
    let mut bytes = [0xABu8; 32];
    bytes[0] = 0xDE;
    bytes[1] = 0xAD;
    let id = PCanonicalId::from_bytes(bytes);

    // Truncated Debug: two bytes then `..`, and nothing of the tail leaks.
    assert_eq!(format!("{id:?}"), "PCanonicalId(dead..)");
    assert!(!format!("{id:?}").contains("abab"));

    // Display is unchanged — the canonical 64-hex encoding.
    let shown = id.to_string();
    assert_eq!(shown.len(), 64);
    assert!(shown.starts_with("dead") && shown.ends_with("ab"));

    // Targeting: a non-persona hash (`TxHash`) keeps its full-hex Debug — computed
    // from `TxHash` itself, not coupled to `PCanonicalId`'s `Display`.
    let tx = TxHash::from_bytes(bytes);
    assert_eq!(format!("{tx:?}"), format!("TxHash({tx})"));
}

#[test]
fn key_image_debug_is_truncated() {
    // Moved verbatim from `shekyl-crypto-pq/src/key_image.rs` with the type
    // (CHAIN_RULES_CRATE.md §3.4): the first two bytes shown, the remaining 30
    // must not appear. `redact, no_display` renders through the same debug
    // builder as `PCanonicalId`, so the shape is `KeyImage(0000..)`; the
    // absence of `Display` is pinned by the crate-docs `compile_fail` doctest,
    // which is the only way to assert a trait is *not* implemented.
    let ki = KeyImage::from_canonical_bytes([0u8; 32]);
    assert_eq!(format!("{ki:?}"), "KeyImage(0000..)");

    let mut bytes = [0xABu8; 32];
    bytes[0] = 0xDE;
    bytes[1] = 0xAD;
    let ki = KeyImage::from_canonical_bytes(bytes);
    assert_eq!(format!("{ki:?}"), "KeyImage(dead..)");
    assert!(!format!("{ki:?}").contains("abab"));
}

#[test]
fn key_image_canonical_constructor_is_the_family_constructor() {
    // `from_canonical_bytes` is kept beside `from_bytes` for its meaning, not
    // for a different value: both wrap the same bytes, and `as_bytes` /
    // `to_bytes` round-trip them. Equality is by bytes.
    let bytes = [0xAB; 32];
    let canonical = KeyImage::from_canonical_bytes(bytes);
    assert_eq!(canonical, KeyImage::from_bytes(bytes));
    assert_eq!(canonical.as_bytes(), &bytes);
    assert_eq!(canonical.to_bytes(), bytes);
    assert_ne!(canonical, KeyImage::from_canonical_bytes([2u8; 32]));
}

#[test]
fn key_image_wire_form_is_the_bare_array() {
    // `#[serde(transparent)]` is what keeps `TransferDetails`' persisted
    // `Option<KeyImage>` byte-identical to `Option<[u8; 32]>` (rule 42). Pinned
    // here so the family's derive, not the old hand-written type, is what the
    // snapshot tests downstream are relying on.
    let bytes = [0x5Au8; 32];
    let typed = postcard::to_allocvec(&KeyImage::from_canonical_bytes(bytes)).unwrap();
    let bare = postcard::to_allocvec(&bytes).unwrap();
    assert_eq!(typed, bare);
    let back: KeyImage = postcard::from_bytes(&typed).unwrap();
    assert_eq!(back.to_bytes(), bytes);
}

#[test]
fn curve_tree_root_is_a_public_hash() {
    // Default arm: a recorded root is a public commitment, so `Debug` and
    // `Display` both render the full hex — and it is a distinct type from the
    // hashes it sits beside (a header's `previous` and `curve_tree_root` are
    // both `[u8; 32]` on the wire; lifted, one cannot be passed for the other).
    let mut bytes = [0u8; 32];
    bytes[0] = 0xDE;
    bytes[1] = 0xAD;
    let root = CurveTreeRoot::from_bytes(bytes);
    let shown = root.to_string();
    assert_eq!(shown.len(), 64);
    assert!(shown.starts_with("dead"));
    assert_eq!(format!("{root:?}"), format!("CurveTreeRoot({shown})"));
    assert_eq!(root.to_bytes(), bytes);
}

#[test]
fn hashes_order_lexicographically_for_btree_keys() {
    // Hashes must be `Ord` so they can key the `BTreeMap`/`BTreeSet`s that
    // wallet-state uses for deterministic txid ordering (PR C). Ordering is
    // lexicographic over the raw bytes, matching `[u8; 32]`.
    use std::collections::BTreeSet;
    use std::vec::Vec;

    let mut a = [0u8; 32];
    a[0] = 1;
    let mut b = [0u8; 32];
    b[0] = 2;

    assert!(TxHash::from_bytes(a) < TxHash::from_bytes(b));

    let set: BTreeSet<TxHash> = [b, a].into_iter().map(TxHash::from_bytes).collect();
    let ordered: Vec<[u8; 32]> = set.into_iter().map(TxHash::to_bytes).collect();
    assert_eq!(
        ordered,
        vec![a, b],
        "BTreeSet must yield byte-lexicographic order"
    );
}

#[test]
fn hashes_are_viewable_as_bytes() {
    // `AsRef<[u8]>` is the single point that lets a typed hash flow into
    // generic byte sinks (`hex::encode`, hashers, length-prefixed writers)
    // without per-call-site `.as_bytes()`. Pin the slice it yields.
    let mut bytes = [0u8; 32];
    bytes[0] = 0xDE;
    bytes[31] = 0xAD;
    let tx = TxHash::from_bytes(bytes);
    let block = BlockHash::from_bytes(bytes);
    let root = CurveTreeRoot::from_bytes(bytes);
    let tx_ref: &[u8] = tx.as_ref();
    let block_ref: &[u8] = block.as_ref();
    let root_ref: &[u8] = root.as_ref();
    assert_eq!(tx_ref, &bytes[..]);
    assert_eq!(block_ref, &bytes[..]);
    assert_eq!(root_ref, &bytes[..]);
}

#[test]
fn timelock_to_unlock_raw_is_block_height_only() {
    // `None` encodes as 0; `Block(h)` encodes as the bare height. (The reverse lift
    // is the consensus-aware `timelock_from_unlock_time` in `shekyl-scanner`, which
    // owns the sentinel discrimination — there is deliberately no context-free
    // `from_unlock_raw` here.)
    assert_eq!(Timelock::None.to_unlock_raw(), 0);
    assert_eq!(Timelock::Block(BlockHeight::from_raw(1)).to_unlock_raw(), 1);
    assert_eq!(
        Timelock::Block(BlockHeight::from_raw(123_456)).to_unlock_raw(),
        123_456
    );
}

#[test]
fn timelock_orders_none_before_block_and_blocks_by_height() {
    use core::cmp::Ordering;
    let none = Timelock::None;
    let low = Timelock::Block(BlockHeight::from_raw(10));
    let high = Timelock::Block(BlockHeight::from_raw(20));

    // `None` is the least element; blocks order by height.
    assert_eq!(none.cmp(&none), Ordering::Equal);
    assert!(none < low);
    assert!(low < high);
    assert_eq!(low.cmp(&low), Ordering::Equal);

    // The "later of the two timelocks wins" selection (`max`) the design relies on.
    assert_eq!(none.max(low), low);
    assert_eq!(low.max(high), high);
}

#[cfg(feature = "schema")]
#[test]
fn schema_is_derivable() {
    // The snapshot harness (in `shekyl-engine-state`) introspects this once a
    // type lands in a persisted block. `Schema::SCHEMA` is a `&NamedType`;
    // assert the derive carries each type's own name (the stable schema
    // identity the harness keys on) rather than comparing brittle `Debug`
    // strings that can drift across `postcard-schema` releases.
    use postcard_schema::Schema;
    assert_eq!(BlockHeight::SCHEMA.name, "BlockHeight");
    assert_eq!(TxHash::SCHEMA.name, "TxHash");
    assert_eq!(PqcAuthHash::SCHEMA.name, "PqcAuthHash");
    assert_eq!(ShardId::SCHEMA.name, "ShardId");
    assert_eq!(OneTimePubkey::SCHEMA.name, "OneTimePubkey");
    assert_ne!(
        BlockHeight::SCHEMA.name,
        TxHash::SCHEMA.name,
        "distinct newtypes must carry distinct named schemas"
    );
    assert_ne!(PqcAuthHash::SCHEMA.name, PrunableHash::SCHEMA.name);
    assert_ne!(BlockWeight::SCHEMA.name, LongTermWeight::SCHEMA.name);
}
