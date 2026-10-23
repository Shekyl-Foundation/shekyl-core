// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`admission_plan`](super::admission_plan) against hand-built bundles.
//!
//! The ordinal, the room under [`COUNTED_DRAWS`](shekyl_types::archival::COUNTED_DRAWS),
//! and a prior epoch's zero contribution. A red edit stores
//! [`DerivedDraw::index`](super::super::DerivedDraw::index) as the key, or
//! lets a prior-epoch bundle reduce the new epoch.

use std::collections::BTreeMap;

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{BundleKept, DrawablePair, PassBitmap};
use shekyl_types::archival::COUNTED_DRAWS;
use shekyl_types::{BlockHeight, PCanonicalId, ShardId};

use super::super::DerivedDraw;
use super::{admission_plan, AdmissionPlanFault};
use crate::SettlementSchedule;

fn persona() -> PCanonicalId {
    PCanonicalId::from_bytes([0x11; 32])
}

fn pair() -> DrawablePair {
    DrawablePair {
        persona: persona(),
        shard: ShardId::from_raw(4),
    }
}

fn bundle(h: BlockHeight, indexes: &[u64]) -> super::super::Admitted {
    let one = pair();
    super::super::Admitted {
        kept: BundleKept {
            h,
            seed: [0x5E; 32],
            passes: PassBitmap::from_passes(
                u32::try_from(indexes.len()).expect("the count fits"),
                [],
            )
            .expect("no pass is out of range"),
        },
        draws: indexes
            .iter()
            .map(|&index| DerivedDraw {
                index,
                pair: one,
                passed: true,
            })
            .collect(),
    }
}

fn schedule() -> SettlementSchedule {
    SettlementSchedule::GENESIS
}

fn open_of(epoch: u64) -> BlockHeight {
    BlockHeight::from_raw(schedule().open_height(epoch))
}

/// Two draws of one pair, with two already visible, reduce by one. The
/// key is the ordinal, so both rows exist even though both selected index 7.
#[test]
fn two_draws_of_a_short_pair_reduce_by_the_room_left() {
    let including = open_of(1);
    let admitted = [bundle(including, &[7, 7])];
    let mut before = BTreeMap::new();
    before.insert((persona(), ShardId::from_raw(4)), 2);
    let plan = admission_plan(including, schedule(), &admitted, &before).expect("the plan");
    let cap = u32::try_from(COUNTED_DRAWS).expect("three");
    assert_eq!(
        plan.issued_short(),
        cap - 2,
        "room left under the cap is one"
    );
    assert_eq!(plan.revealed(), &[including]);
    let issues = plan.epochs();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].epoch(), schedule().epoch_at(including));
    let draws = issues[0].draws();
    assert_eq!(
        draws.iter().map(|draw| draw.draw).collect::<Vec<_>>(),
        vec![0, 1]
    );
    let terms: Vec<_> = issues[0].terms().collect();
    assert_eq!(terms.len(), 2);
    assert_ne!(terms[0], terms[1], "the ordinal is part of the term");
    for (draw, term) in draws.iter().zip(&terms) {
        assert_eq!(
            *term,
            issued_draw_term(
                &draw.persona,
                draw.shard,
                issues[0].epoch(),
                draw.issuing_height,
                draw.draw
            )
        );
    }
}

/// A full pair still issues its draws and adds nothing to the reduction.
#[test]
fn draws_past_the_cap_are_issued_and_do_not_reduce() {
    let including = open_of(1);
    let admitted = [bundle(including, &[1, 1])];
    let mut before = BTreeMap::new();
    let cap = u32::try_from(COUNTED_DRAWS).expect("three");
    before.insert((persona(), ShardId::from_raw(4)), cap);
    let plan = admission_plan(including, schedule(), &admitted, &before).expect("the plan");
    assert_eq!(plan.issued_short(), 0);
    assert_eq!(plan.epochs()[0].draws().len(), 2);
}

/// A bundle from the previous epoch is issued there and leaves the new
/// epoch's shortfall untouched.
#[test]
fn a_prior_epoch_bundle_contributes_nothing() {
    let including = open_of(1);
    let prior = BlockHeight::from_raw(including.to_raw() - 1);
    let admitted = [bundle(prior, &[7, 7])];
    let plan =
        admission_plan(including, schedule(), &admitted, &BTreeMap::new()).expect("the plan");
    assert_eq!(plan.issued_short(), 0);
    assert_eq!(plan.revealed(), &[prior]);
    let issues = &plan.epochs()[0];
    assert_eq!(issues.epoch(), schedule().epoch_at(prior));
    assert_ne!(issues.epoch(), schedule().epoch_at(including));
    assert_eq!(
        issues
            .draws()
            .iter()
            .map(|draw| draw.draw)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert!(issues
        .draws()
        .iter()
        .all(|draw| draw.issuing_height == prior));
    assert!(issues
        .draws()
        .iter()
        .all(|draw| draw.state.revealed_at == including));
}

/// One height, one reveal.
#[test]
fn a_repeated_height_is_refused() {
    let including = open_of(1);
    let admitted = [bundle(including, &[0]), bundle(including, &[1])];
    assert_eq!(
        admission_plan(including, schedule(), &admitted, &BTreeMap::new()),
        Err(AdmissionPlanFault::RepeatedReveal { height: including })
    );
}

/// No bundles is a zero plan. The count writer already stored `issued_short` 0.
#[test]
fn an_empty_admission_reduces_nothing() {
    let including = open_of(1);
    let plan = admission_plan(including, schedule(), &[], &BTreeMap::new()).expect("the plan");
    assert_eq!(plan.issued_short(), 0);
    assert!(plan.revealed().is_empty());
    assert!(plan.epochs().is_empty());
}
