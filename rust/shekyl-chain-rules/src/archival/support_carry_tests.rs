// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The support carry on a driven epoch with test-only admission.
//!
//! The driver steps every block of a span through [`seats_with_carry`] as
//! the switch's transition will: each block's seats are its row, the block
//! whose window closes at the step is handed in with whether its bundle was
//! admitted, and each epoch starts its own carry at its open. Admission is
//! a set of heights whose bundles were never admitted; every other block's
//! bundle is admitted by its close.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use shekyl_archival_retention::{
    support_slot, support_span, DrawableEpoch, SUPPORT_DRAWS_PER_EPOCH,
};
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::archival::{ReceiptSignPk, SupportSeats};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};

use super::*;
use crate::rule_set::SettlementEpochBlocks;

const SEB: u64 = 400;

fn schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(SEB).expect("non-zero"))
}

fn window() -> u64 {
    schedule()
        .challenge_response_blocks()
        .expect("a 400-block epoch has a window")
        .get()
}

fn span() -> u64 {
    support_span(SEB, window()).expect("the window is shorter than the epoch")
}

fn key() -> &'static ReceiptSignPk {
    static KEY: OnceLock<ReceiptSignPk> = OnceLock::new();
    KEY.get_or_init(|| {
        HybridEd25519FnDsa::keypair_from_seeds(&[0x61; 32], &[0x62; 32])
            .expect("fixture receipt key")
            .0
            .to_receipt_sign_pk()
    })
}

/// `tree`'s epoch-relative slots, ascending.
fn slots(tree: &PCanonicalId) -> Vec<u64> {
    let mut slots: Vec<u64> = (0..SUPPORT_DRAWS_PER_EPOCH)
        .map(|i| support_slot(tree, i, SEB, window()).expect("a slot"))
        .collect();
    slots.sort_unstable();
    slots
}

/// A persona whose first slot is early and whose slots are distinct, so a
/// re-seat right after the first close has room.
fn early_tree() -> PCanonicalId {
    (1u8..=255)
        .map(|b| PCanonicalId::from_bytes([b; 32]))
        .find(|p| {
            let s = slots(p);
            s.windows(2).all(|w| w[0] < w[1]) && s[0] + window() + 1 < s[1]
        })
        .expect("some persona starts early")
}

/// A persona with distinct slots, one of which `pick` accepts.
fn tree_with_slot(pick: impl Fn(u64) -> bool) -> (PCanonicalId, u64) {
    (0u16..=u16::MAX)
        .map(|n| {
            let mut bytes = [0x5Cu8; 32];
            bytes[..2].copy_from_slice(&n.to_le_bytes());
            PCanonicalId::from_bytes(bytes)
        })
        .find_map(|p| {
            let s = slots(&p);
            let distinct = s.windows(2).all(|w| w[0] < w[1]);
            let slot = s.iter().copied().find(|&r| pick(r))?;
            distinct.then_some((p, slot))
        })
        .expect("some persona has such a slot")
}

fn snapshot(epoch: u64, tree: PCanonicalId) -> DrawableEpoch {
    DrawableEpoch::new(
        SettlementEpoch::from_raw(epoch),
        8,
        Vec::<(PCanonicalId, &ReceiptSignPk)>::new(),
        [],
    )
    .and_then(|d| d.with_support([(tree, key())]))
    .expect("one member")
}

struct Driven {
    rows: BTreeMap<u64, SupportSeats>,
    /// What each epoch's carry still owed at its last block: what lapsed.
    lapsed: BTreeMap<u64, Vec<(PCanonicalId, u32)>>,
    /// Every tree's owed count after each step.
    owed_trace: Vec<u32>,
}

/// Step every block of epochs `0..epochs` with one member, `tree`, whose
/// bundles are admitted except at `unadmitted`.
fn drive(tree: PCanonicalId, epochs: u64, unadmitted: &BTreeSet<u64>) -> Driven {
    let schedule = schedule();
    let mut rows = BTreeMap::new();
    let mut lapsed = BTreeMap::new();
    let mut owed_trace = Vec::new();
    let mut carry = SupportCarry::new(SettlementEpoch::from_raw(0));
    let mut drawable = snapshot(0, tree);
    for h in 0..epochs * SEB {
        let epoch = schedule.epoch_at(BlockHeight::from_raw(h));
        if epoch != carry.epoch() {
            lapsed.insert(
                carry.epoch().to_raw(),
                carry.owing().map(|(p, o)| (*p, o.get())).collect(),
            );
            carry = SupportCarry::new(epoch);
            drawable = snapshot(epoch.to_raw(), tree);
        }
        let closing = h.checked_sub(window() + 1);
        let closed = closing.and_then(|c| {
            rows.get(&c).map(|seats| WindowClosed {
                seats,
                filed: !unadmitted.contains(&c),
            })
        });
        let seats = seats_with_carry(
            &mut carry,
            &drawable,
            BlockHeight::from_raw(h),
            schedule,
            closed,
        );
        owed_trace.push(carry.owed(&tree).get());
        rows.insert(h, seats);
    }
    lapsed.insert(
        carry.epoch().to_raw(),
        carry.owing().map(|(p, o)| (*p, o.get())).collect(),
    );
    Driven {
        rows,
        lapsed,
        owed_trace,
    }
}

impl Driven {
    /// Heights in epoch `epoch` that seat `tree`.
    fn seated(&self, tree: &PCanonicalId, epoch: u64) -> Vec<u64> {
        self.rows
            .range(epoch * SEB..(epoch + 1) * SEB)
            .filter(|(_, seats)| seats.as_slice().contains(tree))
            .map(|(h, _)| *h)
            .collect()
    }

    /// Seats of `tree` in `epoch` whose bundle was admitted: its filed
    /// support draws.
    fn filed(&self, tree: &PCanonicalId, epoch: u64, unadmitted: &BTreeSet<u64>) -> usize {
        self.seated(tree, epoch)
            .into_iter()
            .filter(|h| !unadmitted.contains(h))
            .count()
    }
}

/// With every bundle admitted, the carry adds nothing: the seats are the
/// schedule's. Red edit: seat a member whenever it is not scheduled (a
/// carried seat with nothing owed).
#[test]
fn with_every_bundle_admitted_the_seats_are_the_schedule() {
    let tree = early_tree();
    let driven = drive(tree, 1, &BTreeSet::new());
    assert_eq!(driven.seated(&tree, 0), slots(&tree));
    assert!(driven.lapsed[&0].is_empty());
}

/// One unfiled seat re-seats at the first usable block after its window
/// closes where the tree has no scheduled seat, and the tree is issued
/// `c`. Red edit: drop the carry (return the schedule's seats); the tree
/// is then issued `c − 1`.
#[test]
fn one_unfiled_seat_reseats_after_its_close_and_the_tree_is_issued_c() {
    let tree = early_tree();
    let first = slots(&tree)[0];
    let unadmitted = BTreeSet::from([first]);
    let driven = drive(tree, 1, &unadmitted);
    let reseat = first + window() + 1;
    assert!(
        driven.seated(&tree, 0).contains(&reseat),
        "re-seated at the close of {first}: {:?}",
        driven.seated(&tree, 0)
    );
    assert_eq!(
        driven.filed(&tree, 0, &unadmitted),
        SUPPORT_DRAWS_PER_EPOCH as usize,
        "the tree is issued c"
    );
    assert!(driven.lapsed[&0].is_empty(), "nothing lapses");
}

/// With no bundle ever admitted, every seat and every re-seat goes
/// unfiled. The count never exceeds the scheduled seats whose windows have
/// closed, so it never passes `c`: a re-seat takes one off before its own
/// close can add one back. Red edit: re-seat without taking one off (drop
/// `reseated`); the count then climbs one a block, to the cap.
#[test]
fn the_count_never_passes_the_scheduled_seats_closed() {
    let tree = early_tree();
    let unadmitted: BTreeSet<u64> = (0..SEB).collect();
    let driven = drive(tree, 1, &unadmitted);
    let scheduled = slots(&tree);
    let most = driven.owed_trace.iter().copied().max().unwrap_or(0);
    assert!(most > 0, "the subject exists: something was owed");
    for (h, owed) in driven.owed_trace.iter().enumerate() {
        let h = h as u64;
        let closed = u32::try_from(scheduled.iter().filter(|&&r| r + window() < h).count())
            .expect("at most c slots");
        assert!(
            *owed <= closed,
            "at {h} the tree is owed {owed}, above the {closed} scheduled seats closed"
        );
    }
    assert!(most <= SUPPORT_DRAWS_PER_EPOCH);
}

/// A draw unfiled at a slot whose close falls past the usable span is not
/// re-seated: it lapses at the epoch's end, and the next epoch seats the
/// tree at its own schedule only. Two cases: a close inside the epoch past
/// the usable span (counted, then lapses), and the last usable slot, whose
/// close is the next epoch's open (never counted). Red edits: re-seat past
/// the usable span (the first case's draw is issued late in the epoch);
/// let a close from the epoch before count (the second case's tree is
/// re-seated in epoch 1).
#[test]
fn a_late_unfiled_draw_lapses_rather_than_crossing_the_epoch() {
    let inside = |r: u64| r + window() + 1 >= span() && r + window() + 1 < SEB;
    let at_the_edge = |r: u64| r == span() - 1;
    for (case, pick) in [
        ("closes inside the epoch", &inside as &dyn Fn(u64) -> bool),
        ("closes at the next open", &at_the_edge),
    ] {
        let (tree, late) = tree_with_slot(pick);
        let unadmitted = BTreeSet::from([late]);
        let driven = drive(tree, 2, &unadmitted);
        assert_eq!(
            driven.seated(&tree, 0),
            slots(&tree),
            "{case}: no re-seat inside epoch 0"
        );
        assert_eq!(
            driven.filed(&tree, 0, &unadmitted),
            SUPPORT_DRAWS_PER_EPOCH as usize - 1,
            "{case}: the late draw is not issued"
        );
        let owed_at_end: Vec<(PCanonicalId, u32)> = if late + window() + 1 < SEB {
            vec![(tree, 1)]
        } else {
            Vec::new()
        };
        assert_eq!(
            driven.lapsed[&0], owed_at_end,
            "{case}: what lapses is the late draw, when its close is inside the epoch"
        );
        let next: Vec<u64> = slots(&tree).iter().map(|r| SEB + r).collect();
        assert_eq!(
            driven.seated(&tree, 1),
            next,
            "{case}: epoch 1 seats the tree at its own schedule"
        );
    }
}
