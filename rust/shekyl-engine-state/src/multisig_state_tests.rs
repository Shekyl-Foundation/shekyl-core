// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group wallet's ceremony records: reservations hold an input for one
//! intent at a time and expire with the intent's reference block; the
//! responder's approvals and the seen-seed fingerprints are a set; the
//! record reads back as written and refuses another version.

use super::*;
use shekyl_crypto_pq::multisig_intent::IntentSeed;

fn inputs(raw: &[u64]) -> Vec<GlobalOutputIndex> {
    raw.iter()
        .map(|&i| GlobalOutputIndex::from_raw(i))
        .collect()
}

const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];

/// An input is reserved for one intent at a time. The same intent may
/// reserve again when the list and the height are the ones already held.
/// A different list, a different height, or another intent's input reserves
/// nothing.
#[test]
fn an_input_is_reserved_for_one_intent() {
    let mut state = MultisigState::empty();
    let height = BlockHeight::from_raw(100);
    state.reserve(&A, &inputs(&[10, 11]), height).unwrap();
    state.reserve(&A, &inputs(&[10, 11]), height).unwrap();
    assert_eq!(state.reservations().len(), 1);
    assert_eq!(
        state.reservations()[0].inputs(),
        inputs(&[10, 11]).as_slice()
    );
    assert_eq!(state.reservations()[0].reference_height(), height);

    assert_eq!(
        state.reserve(&A, &inputs(&[10, 12]), height),
        Err(ReserveError::ReservationDiffers)
    );
    assert_eq!(
        state.reserve(&A, &inputs(&[10, 11]), BlockHeight::from_raw(140)),
        Err(ReserveError::ReservationDiffers)
    );
    assert_eq!(state.reservations().len(), 1);
    assert_eq!(
        state.reservations()[0].inputs(),
        inputs(&[10, 11]).as_slice()
    );
    assert_eq!(state.reservations()[0].reference_height(), height);

    assert_eq!(
        state.reserve(&B, &inputs(&[12, 11]), BlockHeight::from_raw(101)),
        Err(ReserveError::ReservedElsewhere {
            input: GlobalOutputIndex::from_raw(11)
        })
    );
    assert_eq!(state.reservations().len(), 1);
    state
        .reserve(&B, &inputs(&[12]), BlockHeight::from_raw(101))
        .unwrap();
    assert_eq!(state.reservations().len(), 2);
}

/// A reservation is released by name, and by age once its reference block
/// is below the oldest a transaction may still reference.
#[test]
fn a_reservation_is_released_by_name_or_by_age() {
    let mut state = MultisigState::empty();
    state
        .reserve(&A, &inputs(&[10]), BlockHeight::from_raw(100))
        .unwrap();
    state
        .reserve(&B, &inputs(&[11]), BlockHeight::from_raw(150))
        .unwrap();
    assert_eq!(
        state.release_aged(BlockHeight::from_raw(100)),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(state.release_aged(BlockHeight::from_raw(101)), vec![A]);
    assert!(state.release(&B));
    assert!(!state.release(&B));
    assert!(state.reservations().is_empty());
    state
        .reserve(&A, &inputs(&[10, 11]), BlockHeight::from_raw(160))
        .unwrap();
}

/// Approvals and seen seeds are sets of public values: a seed's
/// fingerprint, never the seed.
#[test]
fn approvals_and_seen_seeds_are_sets() {
    let mut state = MultisigState::empty();
    assert!(!state.responder_approved(&A));
    state.record_responder_approval(&A);
    state.record_responder_approval(&A);
    assert!(state.responder_approved(&A));
    assert!(!state.responder_approved(&B));

    let seed = IntentSeed::new(&[7; 32]);
    let fingerprint = seed.fingerprint();
    assert!(!state.has_seen_seed(&fingerprint));
    state.record_seen_seed(&fingerprint);
    state.record_seen_seed(&fingerprint);
    assert!(state.has_seen_seed(&fingerprint));
    assert_eq!(state.seen_seeds().len(), 1);
    assert!(state.seen_seeds().contains(&fingerprint));
    let bytes = state.to_postcard_bytes().unwrap();
    assert!(
        !bytes.windows(32).any(|w| w == [7; 32]),
        "the record holds the seed's fingerprint, not the seed"
    );
}

/// The record reads back as written, and another version is refused by
/// name.
#[test]
fn the_record_round_trips_and_gates_its_version() {
    let mut state = MultisigState::empty();
    state
        .reserve(&A, &inputs(&[3, 4]), BlockHeight::from_raw(9))
        .unwrap();
    state.record_responder_approval(&B);
    state.record_seen_seed(&IntentSeed::new(&[1; 32]).fingerprint());
    let bytes = state.to_postcard_bytes().unwrap();
    assert_eq!(MultisigState::from_postcard_bytes(&bytes).unwrap(), state);

    let mut later = MultisigState::empty();
    later.version = MULTISIG_STATE_VERSION + 1;
    let bytes = later.to_postcard_bytes().unwrap();
    assert!(matches!(
        MultisigState::from_postcard_bytes(&bytes),
        Err(WalletLedgerError::UnsupportedBlockVersion {
            block: "multisig state",
            ..
        })
    ));
}
