// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ring: fill, claim, evict, file, forget, and what it never shows.
//! Every test names the edit that turns it red.

use shekyl_archival_retention::{draw_commit, PassBitmap};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::{SignatureScheme as _, SCHEME_DOMAIN_WITNESS_BUNDLE};

use shekyl_types::BlockCount;

use super::*;

const fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// Two templates for one height commit to different keys and seeds: the
/// ring draws from the OS each time and derives nothing (§4.2). Red edit:
/// derive the seed from the height — the commitments collide.
#[test]
fn two_templates_for_one_height_commit_to_distinct_draws() {
    let ring = WitnessRing::new();
    let a = ring.draw(h(10)).expect("draws");
    let b = ring.draw(h(10)).expect("draws");
    assert_ne!(a, b);
    assert_eq!(ring.candidates(), 2);
}

/// The block at `h` carries one candidate's commitment: that candidate is
/// in flight, its rivals for `h` go, and a candidate for another height
/// stays. Red edit: keep the rivals — the candidate count is 2.
#[test]
fn a_claim_takes_the_mined_candidate_and_drops_its_rivals() {
    let ring = WitnessRing::new();
    let first = ring.draw(h(10)).expect("draws");
    let mined = ring.draw(h(10)).expect("draws");
    let next = ring.draw(h(11)).expect("draws");

    assert!(!ring.claim(h(10), &next), "another height's commitment");
    assert!(ring.claim(h(10), &mined));
    assert_eq!(ring.in_flight(), vec![h(10)]);
    assert_eq!(ring.candidates(), 1);
    assert!(!ring.claim(h(10), &first), "the rival went with the claim");
    assert!(ring.claim(h(11), &next));
    assert_eq!(ring.in_flight(), vec![h(10), h(11)]);
}

/// A candidate [`CANDIDATE_DEPTH`] below the tip lost its race and goes;
/// at the bound the oldest goes first. Red edit: evict at `drawn_for <
/// floor` — the candidate exactly at the depth survives.
#[test]
fn candidates_go_at_the_depth_and_at_the_bound() {
    let ring = WitnessRing::new();
    ring.draw(h(100)).expect("draws");
    ring.draw(h(101)).expect("draws");
    assert_eq!(ring.evict(h(100) + CANDIDATE_DEPTH - BlockCount::ONE), 0);
    assert_eq!(ring.evict(h(100) + CANDIDATE_DEPTH), 1);
    assert_eq!(ring.candidates(), 1);

    let bounded = WitnessRing::bounded(2);
    let oldest = bounded.draw(h(5)).expect("draws");
    bounded.draw(h(6)).expect("draws");
    let newest = bounded.draw(h(7)).expect("draws");
    assert_eq!(bounded.candidates(), 2);
    assert!(!bounded.claim(h(5), &oldest), "the oldest went first");
    assert!(bounded.claim(h(7), &newest));
}

/// Filing signs inside the ring and drops the entry: the bundle's key and
/// seed open the block's `0x0C`, its witness signature verifies over its
/// commitment, and the ring holds nothing of `h` after. Red edit: file
/// without removing — `seed(h)` still answers.
#[test]
fn filing_signs_inside_the_ring_and_takes_the_entry() {
    let ring = WitnessRing::new();
    let commitment = ring.draw(h(20)).expect("draws");
    assert!(ring.claim(h(20), &commitment));
    assert!(ring.seed(h(20)).is_some());

    let (reference, body) = ring
        .file(h(20), PassBitmap::none(), PassBitmap::none(), &[])
        .expect("in flight")
        .expect("signs");
    assert!(ring.seed(h(20)).is_none());
    assert!(ring.in_flight().is_empty());
    assert!(
        ring.file(h(20), PassBitmap::none(), PassBitmap::none(), &[])
            .is_none(),
        "filed once"
    );

    assert_eq!(reference.h(), h(20));
    assert_eq!(
        DrawCommitment::from_bytes(draw_commit(body.witness_public_key(), reference.seed())),
        commitment
    );
    let key = FnDsaHybridPublicKey::from_canonical_bytes(body.witness_public_key()).expect("key");
    let signature =
        FnDsaHybridSignature::from_canonical_bytes(body.witness_signature()).expect("signature");
    HybridEd25519FnDsa
        .verify(
            &key,
            SCHEME_DOMAIN_WITNESS_BUNDLE,
            &reference.kept().commitment(body.records_bytes()),
            &signature,
        )
        .expect("the witness signature verifies");
}

/// A forgotten entry is gone, secrets and all.
#[test]
fn forget_drops_an_entry() {
    let ring = WitnessRing::new();
    let commitment = ring.draw(h(30)).expect("draws");
    assert!(ring.claim(h(30), &commitment));
    assert!(ring.forget(h(30)));
    assert!(!ring.forget(h(30)));
    assert!(ring.seed(h(30)).is_none());
}

/// Every secret the ring holds wipes itself on drop. The bound fails to
/// compile if an entry's type stops being `ZeroizeOnDrop`.
#[test]
fn ring_entries_wipe_themselves() {
    fn wipes_itself_on_drop<T: ZeroizeOnDrop>() {}
    wipes_itself_on_drop::<WitnessSecret>();
    wipes_itself_on_drop::<FnDsaHybridSecretKey>();
    wipes_itself_on_drop::<Zeroizing<[u8; 32]>>();
}

/// Nothing secret reaches a `Debug` output: the ring prints counts and
/// heights, an entry prints a redaction. Red edit: derive `Debug` on the
/// entry — its seed bytes appear.
#[test]
fn the_ring_shows_no_secret() {
    let ring = WitnessRing::new();
    let commitment = ring.draw(h(40)).expect("draws");
    assert!(ring.claim(h(40), &commitment));
    let seed = ring.seed(h(40)).expect("in flight");
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let shown = format!("{ring:?}");
    assert!(shown.contains("in_flight"), "{shown}");
    assert!(!shown.contains(&hex));
    assert!(!shown.contains(&format!("{:?}", &seed[..4])));

    let material = WitnessMaterial::drawn().expect("draws");
    assert_eq!(format!("{material:?}"), "WitnessMaterial([REDACTED])");
}
