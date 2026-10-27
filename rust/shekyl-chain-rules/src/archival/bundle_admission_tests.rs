// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Each admission row, through [`judge_bundles`](super::judge_bundles).
//!
//! One refusal, the row the verifier already names. Red edit: map a
//! refusal onto the neighbouring row.

use shekyl_archival_retention::{bundle_root, BundleBody, BundleRef, PassBitmap};

use super::*;
use crate::census::CenRow;
use crate::harness::bundle::{with_hash, BundleWorld};
use crate::rule_set::RuleSet;

/// [`bundle_root`] over a section a test holds: far fewer than 2³²
/// references, so its one refusal is not this helper's.
fn root_of(refs: &[BundleRef]) -> [u8; 32] {
    bundle_root(refs).expect("a test section's count fits 32 bits")
}

/// Each admission row, through [`super::judge_bundles`]: one refusal, the
/// row the verifier already names.
#[test]
fn judge_bundles_names_each_admission_row() {
    let row = |world: &BundleWorld, reference: &BundleRef, body: &BundleBody, h_incl: u64| {
        super::judge_bundles(
            std::slice::from_ref(reference),
            std::slice::from_ref(body),
            &root_of(std::slice::from_ref(reference)),
            BlockHeight::from_raw(h_incl),
            &world.view,
            &RuleSet::GENESIS,
        )
        .expect_err("a refusal")
        .row()
        .expect("a verdict")
    };
    let world = BundleWorld::new(1);
    let (reference, body) = world.bundle(&[0]);
    let h = world.h.to_raw();

    assert_eq!(
        super::judge_bundles(
            std::slice::from_ref(&reference),
            std::slice::from_ref(&body),
            &[0; 32],
            BlockHeight::from_raw(h + 1),
            &world.view,
            &RuleSet::GENESIS,
        )
        .expect_err("a wrong root")
        .row(),
        Some(CenRow::J29)
    );

    let wide = BundleWorld::new(10);
    let (wide_ref, wide_body) = wide.bundle(&[1]);
    assert_eq!(
        row(&wide, &wide_ref, &wide_body, wide.h.to_raw() + 1),
        CenRow::J30,
        "ten draws exceed the section budget"
    );

    assert_eq!(row(&world, &reference, &body, h + 501), CenRow::J31);

    let mut counted = BundleWorld::new(1);
    let (counted_ref, counted_body) = counted.bundle(&[0]);
    counted.view.counts.insert(counted.h, 0);
    assert_eq!(
        row(
            &counted,
            &counted_ref,
            &counted_body,
            counted.h.to_raw() + 1
        ),
        CenRow::J32
    );

    let mut committed = BundleWorld::new(1);
    let (committed_ref, committed_body) = committed.bundle(&[0]);
    committed.view.commitments.insert(
        committed.h,
        shekyl_types::archival::DrawCommitment::from_bytes([0; 32]),
    );
    assert_eq!(
        row(
            &committed,
            &committed_ref,
            &committed_body,
            committed.h.to_raw() + 1
        ),
        CenRow::J33
    );

    let mut signed = body.as_bytes().to_vec();
    signed[shekyl_archival_retention::BUNDLE_WITNESS_KEY_LEN] ^= 0x01;
    let flipped = BundleBody::decode(&signed).expect("the key still parses");
    let flipped_ref = with_hash(&reference, flipped.prunable_hash());
    assert_eq!(row(&world, &flipped_ref, &flipped, h + 1), CenRow::J34);

    let records = [world.record(0, 3)];
    let (attempt_ref, attempt_body) =
        world.assemble(PassBitmap::from_passes(1, [0]).expect("one pass"), &records);
    assert_eq!(row(&world, &attempt_ref, &attempt_body, h + 1), CenRow::J35);

    let anchored = [world.record_anchored(0, 0, world.h)];
    let (anchor_ref, anchor_body) = world.assemble(
        PassBitmap::from_passes(1, [0]).expect("one pass"),
        &anchored,
    );
    assert_eq!(row(&world, &anchor_ref, &anchor_body, h + 1), CenRow::J36);

    let mut receipt = world.record(0, 0);
    receipt.receipt[0] ^= 0x01;
    let (receipt_ref, receipt_body) = world.assemble(
        PassBitmap::from_passes(1, [0]).expect("one pass"),
        &[receipt],
    );
    assert_eq!(row(&world, &receipt_ref, &receipt_body, h + 1), CenRow::J37);
}
