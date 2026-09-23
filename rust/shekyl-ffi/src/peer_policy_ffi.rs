// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Peer-attribution policy across the C ABI — PWD-B7 drop verdicts, the
//! block-ingest outcome that replaced `bvc`'s bag of bools, and the
//! announce/sync actions P2P takes with those two slots.
//!
//! # What crosses, and what deliberately does not
//!
//! C++ records a classification as an opaque byte on its verification context
//! and writes only through [`shekyl_drop_verdict_classify`] /
//! [`shekyl_block_ingest_record`] / the paired
//! [`shekyl_block_ingest_reject_form`] family. It never compares those
//! bytes against anything. The questions it is allowed to ask are the
//! predicates in this file, and they are answered here. What to *do* after
//! a block ingest is [`shekyl_block_announce_action`] /
//! [`shekyl_block_sync_action`]: C++ asks predicates on the returned
//! action byte. It does not re-order ingest predicates in an if-else.
//!
//! That asymmetry is the point of the boundary. A `switch` on a
//! classification byte in C++ would be a second copy of the rule, in the
//! language whose default this design exists to remove; a predicate call
//! cannot drift, because there is nothing on the C++ side to drift *from*.
//! The `SHEKYL_DROP_VERDICT_*` / `SHEKYL_BLOCK_INGEST_*` constants in
//! `src/shekyl/shekyl_ffi.h` are write-only for C++ — see
//! `tests/unit_tests/peer_policy_drop_verdict.cpp` and
//! `tests/unit_tests/peer_policy_block_ingest.cpp`, which pin them by
//! searching the whole byte domain rather than restating a discriminant.
//! Action bytes have **no** header constants: they are not written from
//! C++.
//!
//! # Total, and infallible by construction
//!
//! Every export accepts any `uint8_t`. An unrecognised drop byte is
//! `DropVerdict::Unclassified`, which does not sever; an unrecognised
//! action byte is the idle arm (do not drop). A C++ caller that passes
//! uninitialised memory, or a byte written by a future revision this
//! binary predates, fails safe rather than severing a peer it cannot
//! classify.

use shekyl_peer_policy::{BlockAnnounceAction, BlockIngest, BlockSyncAction, DropVerdict};

/// Does a rejection carrying this verdict justify dropping the connection that
/// delivered it?
///
/// This is the whole of PWD-B7's rule at the boundary. Callers must ask it
/// rather than testing the byte.
#[no_mangle]
pub extern "C" fn shekyl_drop_verdict_severs(verdict: u8) -> bool {
    DropVerdict::from_byte(verdict).severs()
}

/// Is this rejection a defect of ours, and so worth logging loudly?
///
/// Separate from [`shekyl_drop_verdict_severs`] so the caller asks the two
/// questions it has, rather than receiving a disposition it would have to
/// branch on.
#[no_mangle]
pub extern "C" fn shekyl_drop_verdict_is_internal_failure(verdict: u8) -> bool {
    DropVerdict::from_byte(verdict).is_internal_failure()
}

/// Folds a newly observed classification into the one already recorded, and
/// returns the byte to store. Prefer [`shekyl_drop_verdict_classify`] at a
/// live slot; this exists for tests and for folding two locals.
#[no_mangle]
pub extern "C" fn shekyl_drop_verdict_combine(current: u8, incoming: u8) -> u8 {
    DropVerdict::from_byte(current)
        .combine(DropVerdict::from_byte(incoming))
        .to_byte()
}

/// Writes `incoming` into `slot` through [`DropVerdict::combine`].
///
/// This is the C++ write path. A null `slot` is a no-op so callers with no
/// peer (importer, miner, generated-chain tests) pass null rather than a
/// dummy they ignore.
///
/// # Safety
///
/// `slot` may be null. If non-null it must point to a writable `u8` that
/// lives for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_drop_verdict_classify(slot: *mut u8, incoming: u8) {
    if slot.is_null() {
        return;
    }
    // SAFETY: non-null, caller-owned writable byte.
    unsafe {
        DropVerdict::classify_in_place(&mut *slot, DropVerdict::from_byte(incoming));
    }
}

/// Did this ingest land the block on the main chain?
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_is_added(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).is_added()
}

/// Did we already have this hash?
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_already_exists(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).already_exists()
}

/// Is the parent unknown?
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_is_orphaned(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).is_orphaned()
}

/// Should P2P re-request missing compact-block txs rather than drop?
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_missing_txs(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).missing_txs()
}

/// Was the block refused? Drop is still [`shekyl_drop_verdict_severs`].
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_is_rejected(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).is_rejected()
}

/// Should a drop (if any) carry the heavier PoW-DoS score?
#[no_mangle]
pub extern "C" fn shekyl_block_ingest_is_bad_pow(outcome: u8) -> bool {
    BlockIngest::from_byte(outcome).is_bad_pow()
}

/// Folds a newly recorded outcome into `slot`. First writer wins.
/// A null `slot` is a no-op.
///
/// # Safety
///
/// `slot` may be null. If non-null it must point to a writable `u8` that
/// lives for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_record(slot: *mut u8, incoming: u8) {
    if slot.is_null() {
        return;
    }
    // SAFETY: non-null, caller-owned writable byte.
    unsafe {
        BlockIngest::record_in_place(&mut *slot, BlockIngest::from_byte(incoming));
    }
}

/// Record a form rejection on both slots. Either pointer null → no-op
/// (do not half-write).
///
/// # Safety
///
/// Each pointer may be null. If non-null it must point to a writable
/// `u8` that lives for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_reject_form(outcome: *mut u8, drop: *mut u8) {
    write_reject_both(outcome, drop, BlockIngest::write_reject_form);
}

/// Record a local-policy / our-state rejection on both slots.
///
/// # Safety
///
/// See [`shekyl_block_ingest_reject_form`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_reject_state(outcome: *mut u8, drop: *mut u8) {
    write_reject_both(outcome, drop, BlockIngest::write_reject_state);
}

/// Record an internal-failure rejection on both slots.
///
/// # Safety
///
/// See [`shekyl_block_ingest_reject_form`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_reject_internal(outcome: *mut u8, drop: *mut u8) {
    write_reject_both(outcome, drop, BlockIngest::write_reject_internal);
}

/// Record a bad-PoW rejection on both slots.
///
/// # Safety
///
/// See [`shekyl_block_ingest_reject_form`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_reject_bad_pow(outcome: *mut u8, drop: *mut u8) {
    write_reject_both(outcome, drop, BlockIngest::write_reject_bad_pow);
}

/// Record a rejection whose drop classification already happened on the
/// tx path. Fold `incoming_drop`; do not re-interpret it.
///
/// # Safety
///
/// See [`shekyl_block_ingest_reject_form`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_block_ingest_reject_with_drop(
    outcome: *mut u8,
    drop: *mut u8,
    incoming_drop: u8,
) {
    if outcome.is_null() || drop.is_null() {
        return;
    }
    // SAFETY: both pointers non-null, caller-owned writable bytes.
    unsafe {
        BlockIngest::write_reject_with_drop(
            &mut *outcome,
            &mut *drop,
            DropVerdict::from_byte(incoming_drop),
        );
    }
}

/// Pair a reject write onto both ABI slots.
///
/// # Safety
///
/// Each pointer may be null. If this function proceeds, both are
/// non-null caller-owned writable `u8`s that live for the call.
unsafe fn write_reject_both(outcome: *mut u8, drop: *mut u8, write: fn(&mut u8, &mut u8)) {
    if outcome.is_null() || drop.is_null() {
        return;
    }
    // SAFETY: both pointers non-null, caller-owned writable bytes.
    unsafe {
        write(&mut *outcome, &mut *drop);
    }
}

/// What the announce path should do with these two slots and the
/// `handle_*` return. C++ asks the predicates below; it does not
/// switch on this byte.
#[no_mangle]
pub extern "C" fn shekyl_block_announce_action(outcome: u8, drop: u8, handle_ok: bool) -> u8 {
    BlockAnnounceAction::from_ingest(
        BlockIngest::from_byte(outcome),
        DropVerdict::from_byte(drop),
        handle_ok,
    )
    .to_byte()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_re_request_txs(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).re_request_txs()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_drop(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).drop_peer()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_heavier_score(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).heavier_score()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_our_failure(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).our_failure()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_relay(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).relay()
}

#[no_mangle]
pub extern "C" fn shekyl_block_announce_request_history(action: u8) -> bool {
    BlockAnnounceAction::from_byte(action).request_history()
}

/// What the GET_OBJECTS sync path should do with these two slots.
#[no_mangle]
pub extern "C" fn shekyl_block_sync_action(outcome: u8, drop: u8) -> u8 {
    BlockSyncAction::from_ingest(
        BlockIngest::from_byte(outcome),
        DropVerdict::from_byte(drop),
    )
    .to_byte()
}

#[no_mangle]
pub extern "C" fn shekyl_block_sync_drop(action: u8) -> bool {
    BlockSyncAction::from_byte(action).drop_peer()
}

#[no_mangle]
pub extern "C" fn shekyl_block_sync_heavier_score(action: u8) -> bool {
    BlockSyncAction::from_byte(action).heavier_score()
}

#[no_mangle]
pub extern "C" fn shekyl_block_sync_orphan_resync(action: u8) -> bool {
    BlockSyncAction::from_byte(action).orphan_resync()
}

#[cfg(test)]
mod tests {
    use super::{
        shekyl_block_announce_action, shekyl_block_announce_drop,
        shekyl_block_announce_heavier_score, shekyl_block_announce_our_failure,
        shekyl_block_announce_re_request_txs, shekyl_block_announce_relay,
        shekyl_block_announce_request_history, shekyl_block_ingest_already_exists,
        shekyl_block_ingest_is_added, shekyl_block_ingest_is_bad_pow,
        shekyl_block_ingest_is_orphaned, shekyl_block_ingest_is_rejected,
        shekyl_block_ingest_missing_txs, shekyl_block_ingest_record,
        shekyl_block_ingest_reject_form, shekyl_block_ingest_reject_internal,
        shekyl_block_sync_action, shekyl_block_sync_drop, shekyl_block_sync_heavier_score,
        shekyl_block_sync_orphan_resync, shekyl_drop_verdict_classify, shekyl_drop_verdict_combine,
        shekyl_drop_verdict_is_internal_failure, shekyl_drop_verdict_severs,
    };
    use shekyl_peer_policy::{BlockAnnounceAction, BlockIngest, BlockSyncAction, DropVerdict};

    /// The exports are total over the byte and agree with the crate they
    /// marshal — checked across the whole domain, because the bytes this
    /// boundary will actually be handed wrong are the ones no name covers.
    #[test]
    fn the_exports_agree_with_the_rule_over_every_byte() {
        for byte in u8::MIN..=u8::MAX {
            let verdict = DropVerdict::from_byte(byte);
            assert_eq!(shekyl_drop_verdict_severs(byte), verdict.severs());
            assert_eq!(
                shekyl_drop_verdict_is_internal_failure(byte),
                verdict.is_internal_failure()
            );
        }
    }

    /// The value C++ writes for "the sender chose these bytes" is the only one
    /// that comes back severing.
    #[test]
    fn exactly_one_byte_severs_across_the_boundary() {
        let severing: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|byte| shekyl_drop_verdict_severs(*byte))
            .collect();
        assert_eq!(severing, vec![DropVerdict::AttributableForm.to_byte()]);
    }

    /// Folding is what C++ assigns through, so it must also be total: over all
    /// 65536 ordered byte pairs, a fold severs only if one of its inputs
    /// already did. Nothing a caller can write — an unrecognised byte, a
    /// future revision's value, uninitialised memory on either side — can
    /// manufacture a drop that neither input asked for.
    #[test]
    fn folding_can_only_sever_if_an_input_severs() {
        for current in u8::MIN..=u8::MAX {
            for incoming in u8::MIN..=u8::MAX {
                if !shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(current, incoming)) {
                    continue;
                }
                assert!(
                    shekyl_drop_verdict_severs(current) || shekyl_drop_verdict_severs(incoming),
                    "combine({current}, {incoming}) severs though neither input does"
                );
            }
        }
    }

    /// And the direction that keeps the test above from passing on a rule that
    /// never severs: a recognised no-drop classification on either side is
    /// enough to stop a form verdict, while a form verdict alone gets through.
    #[test]
    fn a_recognised_no_drop_input_stops_a_form_verdict_but_nothing_else_does() {
        let form = DropVerdict::AttributableForm.to_byte();
        for no_drop in [
            DropVerdict::PolicyOrState.to_byte(),
            DropVerdict::InternalFailure.to_byte(),
        ] {
            assert!(!shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(
                no_drop, form
            )));
            assert!(!shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(
                form, no_drop
            )));
        }
        assert!(shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(
            DropVerdict::Unclassified.to_byte(),
            form
        )));
        assert!(shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(
            form, form
        )));
    }

    /// The write path agrees with combine, and a null slot is a no-op so a
    /// caller with no peer can pass null without manufacturing a drop.
    #[test]
    fn classify_in_place_matches_combine_and_null_is_a_noop() {
        let form = DropVerdict::AttributableForm.to_byte();
        let state = DropVerdict::PolicyOrState.to_byte();
        let mut slot = DropVerdict::Unclassified.to_byte();
        unsafe { shekyl_drop_verdict_classify(&raw mut slot, form) };
        assert!(shekyl_drop_verdict_severs(slot));
        unsafe { shekyl_drop_verdict_classify(&raw mut slot, state) };
        assert!(!shekyl_drop_verdict_severs(slot));
        assert_eq!(slot, state);
        unsafe { shekyl_drop_verdict_classify(std::ptr::null_mut(), form) };
    }

    /// Block-ingest predicates agree with the crate over the whole byte
    /// domain — including bytes no arm names.
    #[test]
    fn block_ingest_predicates_agree_over_every_byte() {
        for byte in u8::MIN..=u8::MAX {
            let outcome = BlockIngest::from_byte(byte);
            assert_eq!(shekyl_block_ingest_is_added(byte), outcome.is_added());
            assert_eq!(
                shekyl_block_ingest_already_exists(byte),
                outcome.already_exists()
            );
            assert_eq!(shekyl_block_ingest_is_orphaned(byte), outcome.is_orphaned());
            assert_eq!(shekyl_block_ingest_missing_txs(byte), outcome.missing_txs());
            assert_eq!(shekyl_block_ingest_is_rejected(byte), outcome.is_rejected());
            assert_eq!(shekyl_block_ingest_is_bad_pow(byte), outcome.is_bad_pow());
        }
    }

    /// First writer wins at the boundary, and a null slot is a no-op.
    #[test]
    fn block_ingest_record_keeps_the_first_arm_and_null_is_a_noop() {
        let mut slot = BlockIngest::Unclassified.to_byte();
        unsafe { shekyl_block_ingest_record(&raw mut slot, BlockIngest::Rejected.to_byte()) };
        assert!(shekyl_block_ingest_is_rejected(slot));
        unsafe {
            shekyl_block_ingest_record(&raw mut slot, BlockIngest::AddedToMainChain.to_byte())
        };
        assert!(shekyl_block_ingest_is_rejected(slot));
        assert!(!shekyl_block_ingest_is_added(slot));
        unsafe {
            shekyl_block_ingest_record(
                std::ptr::null_mut(),
                BlockIngest::AddedToMainChain.to_byte(),
            )
        };
    }

    /// Pairing writes both slots, and a null on either side is a no-op so
    /// C++ cannot half-write.
    #[test]
    fn reject_form_pairs_both_slots_and_either_null_is_a_noop() {
        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        unsafe { shekyl_block_ingest_reject_form(&raw mut outcome, &raw mut drop) };
        assert!(shekyl_block_ingest_is_rejected(outcome));
        assert!(shekyl_drop_verdict_severs(drop));

        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        unsafe { shekyl_block_ingest_reject_internal(&raw mut outcome, &raw mut drop) };
        assert!(shekyl_block_ingest_is_rejected(outcome));
        assert!(!shekyl_drop_verdict_severs(drop));

        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        unsafe { shekyl_block_ingest_reject_form(std::ptr::null_mut(), &raw mut drop) };
        assert_eq!(outcome, BlockIngest::Unclassified.to_byte());
        assert_eq!(drop, DropVerdict::Unclassified.to_byte());
        unsafe { shekyl_block_ingest_reject_form(&raw mut outcome, std::ptr::null_mut()) };
        assert_eq!(outcome, BlockIngest::Unclassified.to_byte());
        assert_eq!(drop, DropVerdict::Unclassified.to_byte());
    }

    /// Announce/sync FFI agrees with the crate over every named pair, and
    /// unrecognised action bytes are idle (do not drop).
    #[test]
    fn announce_and_sync_actions_agree_with_the_crate() {
        for outcome in u8::MIN..=u8::MAX {
            for drop in u8::MIN..=u8::MAX {
                let expected = BlockAnnounceAction::from_ingest(
                    BlockIngest::from_byte(outcome),
                    DropVerdict::from_byte(drop),
                    true,
                );
                let action = shekyl_block_announce_action(outcome, drop, true);
                assert_eq!(action, expected.to_byte());
                assert_eq!(
                    shekyl_block_announce_re_request_txs(action),
                    expected.re_request_txs()
                );
                assert_eq!(shekyl_block_announce_drop(action), expected.drop_peer());
                assert_eq!(
                    shekyl_block_announce_heavier_score(action),
                    expected.heavier_score()
                );
                assert_eq!(
                    shekyl_block_announce_our_failure(action),
                    expected.our_failure()
                );
                assert_eq!(shekyl_block_announce_relay(action), expected.relay());
                assert_eq!(
                    shekyl_block_announce_request_history(action),
                    expected.request_history()
                );

                let expected_sync = BlockSyncAction::from_ingest(
                    BlockIngest::from_byte(outcome),
                    DropVerdict::from_byte(drop),
                );
                let sync = shekyl_block_sync_action(outcome, drop);
                assert_eq!(sync, expected_sync.to_byte());
                assert_eq!(shekyl_block_sync_drop(sync), expected_sync.drop_peer());
                assert_eq!(
                    shekyl_block_sync_heavier_score(sync),
                    expected_sync.heavier_score()
                );
                assert_eq!(
                    shekyl_block_sync_orphan_resync(sync),
                    expected_sync.orphan_resync()
                );
            }
        }
    }

    #[test]
    fn unknown_action_bytes_do_not_drop() {
        for byte in u8::MIN..=u8::MAX {
            let announce = BlockAnnounceAction::from_byte(byte);
            let hits = [
                shekyl_block_announce_re_request_txs(byte),
                shekyl_block_announce_drop(byte),
                shekyl_block_announce_our_failure(byte),
                shekyl_block_announce_relay(byte),
                shekyl_block_announce_request_history(byte),
            ]
            .into_iter()
            .filter(|h| *h)
            .count();
            assert!(hits <= 1, "announce byte {byte} hit {hits}");
            if shekyl_block_announce_heavier_score(byte) {
                assert!(shekyl_block_announce_drop(byte));
            }
            if byte == 0 || byte >= 7 {
                assert_eq!(announce, BlockAnnounceAction::None);
                assert_eq!(hits, 0);
            }

            if byte >= 4 {
                assert!(!shekyl_block_sync_drop(byte));
                assert!(!shekyl_block_sync_orphan_resync(byte));
                assert!(!shekyl_block_sync_heavier_score(byte));
            }
        }
    }
}
