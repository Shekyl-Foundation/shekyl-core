// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the foundational domain newtypes: transparency (wire
//! identity to the wrapped primitive), the height/count algebra, and the
//! hex hash formatting.

use super::*;

#[test]
fn edge_round_trip() {
    assert_eq!(BlockHeight::from_raw(42).to_raw(), 42);
    assert_eq!(GlobalOutputIndex::from_raw(7).to_raw(), 7);
    assert!(BlockHeight::ZERO.is_zero());
    assert!(!BlockCount::from_raw(1).is_zero());

    let bytes = [3u8; 32];
    assert_eq!(TxHash::from_bytes(bytes).to_bytes(), bytes);
    assert_eq!(BlockHash::from_bytes(bytes).as_bytes(), &bytes);
}

#[test]
fn serde_is_transparent_to_inner_u64() {
    // `#[serde(transparent)]` means the postcard wire bytes of the newtype
    // are byte-identical to the bare `u64` — the property that lets a
    // persisted field adopt the newtype without a format-version bump.
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
fn hashes_order_lexicographically_for_btree_keys() {
    // Hashes must be `Ord` so they can key the `BTreeMap`/`BTreeSet`s that
    // wallet-state uses for deterministic txid ordering (PR C). Ordering is
    // lexicographic over the raw bytes, matching `[u8; 32]`.
    use std::collections::BTreeSet;

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
    let tx_ref: &[u8] = tx.as_ref();
    let block_ref: &[u8] = block.as_ref();
    assert_eq!(tx_ref, &bytes[..]);
    assert_eq!(block_ref, &bytes[..]);
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
    assert_ne!(
        BlockHeight::SCHEMA.name,
        TxHash::SCHEMA.name,
        "distinct newtypes must carry distinct named schemas"
    );
}
