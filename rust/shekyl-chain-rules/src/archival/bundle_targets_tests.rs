// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`draw_targets`] against the fixture view: what the producer of `h`
//! reads is what [`verify_bundle`] derives (`SO-D12` increment 4c).
//!
//! The parity is by construction — both call one selection and one
//! support derivation — and these tests hold it from the outside: for
//! every draw, the pair the producer would read is the pair in
//! `Admitted::draws`, and every support seat is the observation the
//! verifier writes. Every test names the edit that turns it red.

use shekyl_archival_retention::{support_challenge_nonce, PassBitmap, PassStream};

use super::*;
use crate::harness::bundle::{fixture_block_hash, BundleReadFaulted, BundleWorld};

const WIDTH: u64 = 64;

fn targets(world: &BundleWorld) -> Result<DrawTargets, BundleRefused<BundleReadFaulted>> {
    draw_targets(&world.view, world.h, &world.seed, &RuleSet::GENESIS)
}

fn seat(world: &BundleWorld, n: usize) -> SupportSeat {
    SupportSeat {
        persona: world.personas[n].persona,
        receipt_key: world.personas[n].receipt_public_key.clone(),
    }
}

/// Every economy draw: the producer's pair, index and receipt key are the
/// verifier's, including a draw that visibly-short pushed off its first
/// pick. Red edit: let `draw_targets` select with `count + 1`, or skip
/// the visibly-short read — the pairs differ from `Admitted::draws`.
#[test]
fn the_producers_economy_pairs_are_the_verifiers_draws() {
    let mut world = BundleWorld::new(6);
    let first_pick = world.selected(2);
    world.view.short.insert((world.h, first_pick));
    let produced = targets(&world).expect("the fixture answers every read");
    assert_eq!(produced.h, world.h);
    assert_eq!(produced.hash, fixture_block_hash(world.h));
    assert!(produced.support.is_empty());

    let (reference, body) = world.bundle(&[]);
    let admitted = verify_bundle(
        &reference,
        &body,
        world.h + shekyl_types::BlockCount::ONE,
        &world.view,
        &RuleSet::GENESIS,
    )
    .expect("the all-miss bundle admits");
    assert_eq!(produced.economy.len(), admitted.draws.len());
    for (target, derived) in produced.economy.iter().zip(&admitted.draws) {
        assert_eq!(target.index, derived.index, "draw {}", target.draw);
        assert_eq!(target.pair, derived.pair, "draw {}", target.draw);
        assert_eq!(
            Some(&target.receipt_key),
            world.drawable_epoch().receipt_key(target.index),
            "draw {}",
            target.draw
        );
    }
    assert_eq!(
        (0..6).collect::<Vec<u32>>(),
        produced.economy.iter().map(|t| t.draw).collect::<Vec<_>>()
    );
}

/// Every support draw: the producer's seat and shard are the verifier's
/// observation, and the receipt the producer would collect on that seat
/// admits. Red edit: select the support shard with the economy label, or
/// zip the roster from 1 — the observation's shard or persona differs.
#[test]
fn the_producers_support_seats_are_the_verifiers_observations() {
    let mut world = BundleWorld::new(2);
    world.view.archive_width.insert(world.h, WIDTH);
    world
        .view
        .support_roster
        .insert(world.h, vec![seat(&world, 1), seat(&world, 2)]);
    let produced = targets(&world).expect("the fixture answers every read");
    assert_eq!(produced.support.len(), 2);

    // The producer reads seat 1 and passes it; the record is signed over
    // the target's shard, under the target's nonce.
    let hash = fixture_block_hash(world.h);
    let pass = &produced.support[1];
    let nonce = support_challenge_nonce(&world.seed, hash.as_bytes(), pass.draw, 0);
    let record = world.persona_record(2, pass.shard.to_raw(), PassStream::Support, &nonce);
    let (reference, body) = world.assemble_support(
        PassBitmap::from_passes(world.count, []).expect("no economy passes"),
        PassBitmap::from_passes(2, [1]).expect("support bit 1"),
        &[record],
    );
    let admitted = verify_bundle(
        &reference,
        &body,
        world.h + shekyl_types::BlockCount::ONE,
        &world.view,
        &RuleSet::GENESIS,
    )
    .expect("the support pass the producer collected admits");
    assert_eq!(admitted.support.len(), produced.support.len());
    for (target, observed) in produced.support.iter().zip(&admitted.support) {
        assert_eq!(target.draw, observed.draw);
        assert_eq!(target.persona, observed.persona);
        assert_eq!(target.shard, observed.shard);
    }
    assert!(admitted.support[1].passed && !admitted.support[0].passed);
    assert_eq!(
        produced.support[0].receipt_key.to_receipt_sign_pk(),
        world.personas[1].receipt_public_key
    );
}

/// A block that issued nothing on either stream has no target and reads
/// no drawable epoch. Red edit: read `D` before checking the count — the
/// world without an epoch answers unanswered instead of empty.
#[test]
fn a_block_with_no_draws_has_no_targets() {
    let mut world = BundleWorld::new(0);
    world.view.drawable_epochs.clear();
    let produced = targets(&world).expect("nothing to derive");
    assert!(produced.economy.is_empty());
    assert!(produced.support.is_empty());
}

/// The view's holes are the producer's unanswered, never a verdict: no
/// count, no drawable epoch, no roster. Red edit: map a missing count to
/// zero — the first assertion gets an empty target list.
#[test]
fn a_hole_in_the_view_is_unanswered() {
    let mut world = BundleWorld::new(3);
    world.view.counts.clear();
    assert_eq!(
        targets(&world),
        Err(BundleRefused::Unanswered(BundleUnanswered::DrawCount {
            height: world.h
        }))
    );

    let mut world = BundleWorld::new(3);
    world.view.drawable_epochs.clear();
    let epoch = RuleSet::GENESIS.settlement_schedule().epoch_at(world.h);
    assert_eq!(
        targets(&world),
        Err(BundleRefused::Unanswered(BundleUnanswered::DrawableEpoch {
            epoch
        }))
    );
}
