// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The seats over a snapshot.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use shekyl_archival_retention::{
    support_slot, support_span, DrawableEpoch, DrawablePair, SUPPORT_DRAWS_PER_EPOCH,
};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::archival::ReceiptSignPk;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use super::*;
use crate::rule_set::SettlementEpochBlocks;

const TREE_A: PCanonicalId = PCanonicalId::from_bytes([0x11; 32]);
const TREE_B: PCanonicalId = PCanonicalId::from_bytes([0x77; 32]);
const COMPACT: PCanonicalId = PCanonicalId::from_bytes([0x40; 32]);

fn key(seed: u8) -> ReceiptSignPk {
    HybridEd25519FnDsa::keypair_from_seeds(&[seed; 32], &[seed ^ 0x5A; 32])
        .expect("fixture receipt key")
        .0
        .to_receipt_sign_pk()
}

fn keys() -> &'static [ReceiptSignPk; 3] {
    static KEYS: OnceLock<[ReceiptSignPk; 3]> = OnceLock::new();
    KEYS.get_or_init(|| [key(1), key(2), key(3)])
}

fn schedule(blocks: u64) -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(blocks).expect("non-zero"))
}

/// Epoch `epoch`'s snapshot: one compact pair, and the two trees as
/// members at `width`.
fn snapshot(epoch: SettlementEpoch, width: u64) -> DrawableEpoch {
    let k = keys();
    DrawableEpoch::new(
        epoch,
        width,
        [(COMPACT, &k[2])],
        [DrawablePair {
            persona: COMPACT,
            shard: ShardId::from_raw(0),
        }],
    )
    .and_then(|d| d.with_support([(TREE_B, &k[1]), (TREE_A, &k[0])]))
    .expect("two members over a non-empty archive")
}

/// Over a whole epoch, each member is seated exactly at its `c` slots, all
/// inside `SEB − W₂`, once per block, and a pair holder never. The archive
/// width selects shards and does not move a seat: two widths seat alike.
/// Red edits: spread the slots over `0..SEB` in `support_slot` (a seat
/// lands in the last `W₂`); seat every member at every height (counts pass
/// `c`); drop the persona filter (the compact holder is seated).
#[test]
fn each_member_is_seated_at_its_c_slots_and_nowhere_else() {
    let schedule = schedule(400);
    let seb = schedule.blocks().get();
    let window = schedule
        .challenge_response_blocks()
        .expect("a 400-block epoch has a window")
        .get();
    let span = support_span(seb, window).expect("the window is shorter than the epoch");
    let epoch = SettlementEpoch::from_raw(3);
    let open = schedule.open_height(epoch.to_raw());
    for width in [1, 40] {
        let drawable = snapshot(epoch, width);
        let mut seated: BTreeMap<PCanonicalId, Vec<u64>> = BTreeMap::new();
        for relative in 0..seb {
            let seats =
                scheduled_seats(&drawable, BlockHeight::from_raw(open + relative), schedule);
            assert!(
                seats.as_slice().windows(2).all(|w| w[0] < w[1]),
                "persona order"
            );
            for persona in seats.as_slice() {
                seated.entry(*persona).or_default().push(relative);
            }
        }
        assert!(!seated.contains_key(&COMPACT), "a pair holder is no member");
        // Many members, so the span bound is met by hundreds of slots and
        // not only the two trees'.
        let many = DrawableEpoch::new(
            epoch,
            width,
            Vec::<(PCanonicalId, &ReceiptSignPk)>::new(),
            [],
        )
        .and_then(|d| {
            d.with_support((0x80u8..0xA0).map(|b| (PCanonicalId::from_bytes([b; 32]), &keys()[0])))
        })
        .expect("thirty-two members");
        let mut seats_of_many = 0usize;
        for relative in 0..seb {
            let seats = scheduled_seats(&many, BlockHeight::from_raw(open + relative), schedule);
            assert!(
                seats.is_empty() || relative < span,
                "a seat at {relative} would close its window after the epoch"
            );
            seats_of_many += seats.len();
        }
        assert_eq!(seats_of_many, 32 * SUPPORT_DRAWS_PER_EPOCH as usize);
        for tree in [TREE_A, TREE_B] {
            let mut expected: Vec<u64> = (0..SUPPORT_DRAWS_PER_EPOCH)
                .map(|i| support_slot(&tree, i, seb, window).expect("a slot"))
                .collect();
            expected.sort_unstable();
            expected.dedup();
            assert_eq!(
                seated.get(&tree).map(Vec::len),
                Some(SUPPORT_DRAWS_PER_EPOCH as usize),
                "{tree:?} at width {width}: c seats"
            );
            assert_eq!(seated[&tree], expected, "{tree:?} at its slots");
            assert!(
                seated[&tree].iter().all(|&r| r < span),
                "every seat leaves its window inside the epoch"
            );
        }
    }
}

/// A schedule with no response window seats nobody, and an epoch with no
/// member seats nobody. Red edit: fall back to a stand-in window.
#[test]
fn no_window_or_no_member_seats_nobody() {
    let windowless = schedule(10);
    assert!(windowless.challenge_response_blocks().is_none());
    let epoch = SettlementEpoch::from_raw(0);
    let drawable = snapshot(epoch, 4);
    for h in 0..10 {
        assert!(scheduled_seats(&drawable, BlockHeight::from_raw(h), windowless).is_empty());
    }
    let windowed = schedule(400);
    let empty = DrawableEpoch::empty(epoch);
    for h in 0..400 {
        assert!(scheduled_seats(&empty, BlockHeight::from_raw(h), windowed).is_empty());
    }
}
