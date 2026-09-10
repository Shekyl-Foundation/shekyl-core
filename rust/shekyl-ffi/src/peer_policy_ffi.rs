// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Peer-attribution drop rule across the C ABI — PWD-B7.
//!
//! # What crosses, and what deliberately does not
//!
//! C++ records a classification as an opaque byte on its verification context
//! and writes only through [`shekyl_drop_verdict_classify`]. It never compares
//! that byte against anything. The two questions it is allowed to ask are
//! [`shekyl_drop_verdict_severs`] and
//! [`shekyl_drop_verdict_is_internal_failure`], and both are answered here.
//!
//! That asymmetry is the point of the boundary. A `switch` on the byte in C++
//! would be a second copy of the rule, in the language whose default this
//! design exists to remove; a predicate call cannot drift, because there is
//! nothing on the C++ side to drift *from*. The `SHEKYL_DROP_VERDICT_*`
//! constants in `src/shekyl/shekyl_ffi.h` are write-only for C++ — see
//! `tests/unit_tests/peer_policy_drop_verdict.cpp`, which pins them by
//! searching the whole byte domain for the value that severs rather than by
//! restating any number.
//!
//! # Total, and infallible by construction
//!
//! Every export accepts any `uint8_t`. An unrecognised byte is
//! `DropVerdict::Unclassified`, which does not sever — so a C++ caller that
//! passes uninitialised memory, or a byte written by a future revision this
//! binary predates, fails safe rather than severing a peer it cannot classify.

use shekyl_peer_policy::DropVerdict;

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

#[cfg(test)]
mod tests {
    use super::{
        shekyl_drop_verdict_classify, shekyl_drop_verdict_combine,
        shekyl_drop_verdict_is_internal_failure, shekyl_drop_verdict_severs,
    };
    use shekyl_peer_policy::DropVerdict;

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
}
