// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Peer-attribution policy — PWD-B7 of `docs/design/SHEKYL_P2P_PROTOCOL.md`.
//!
//! # The rule this crate exists to make unbreakable
//!
//! > Drop the peer only when the rejection is *attributable to the sender's
//! > choice*. That requires two things together — the rejection must describe
//! > the INPUT rather than our own state, *and* the rule it fails must be
//! > UNIVERSAL rather than local policy.
//!
//! # Why this is a type and not a `bool`
//!
//! The mechanism this replaces was `bool m_no_drop_offense`: a carve-out list
//! whose *absence* meant "droppable". That default is the defect. Absence does
//! not identify *form* — it identifies everything that is not one of the four
//! carve-outs, and that set includes **our own failures**. A pool-bookkeeping
//! invariant tripping, or a storage exception, returned with the flag unset and
//! severed an innocent peer: our own storage throwing partitioned us from the
//! network.
//!
//! So the surface is affirmative and tri-state, and the *unset* arm — along
//! with any byte a future writer has not taught this crate about — resolves to
//! [`DropVerdict::Unclassified`], which does not sever. The asymmetry is
//! deliberate and is the whole reason the default points this way:
//!
//! - Mis-classifying a form failure as internal keeps **one** hostile
//!   connection alive, which PWD-B1's token bucket is what charges.
//! - The opposite default partitions the network on **our own bugs**.
//!
//! A drop rule doing rate limiting's job is what severs honest peers, so the
//! two are kept apart: this crate answers *"may we sever?"*, never *"is this
//! peer expensive?"*.
//!
//! # Why the crate boundary is here
//!
//! Not `shekyl-relay`: that crate's charter is the live relay *scheduler*, and
//! its own module docs argue that charter erosion is the failure mode worth
//! guarding against. Not `shekyl-consensus`: attributability is explicitly
//! *not* a consensus question — two of the four original carve-outs are
//! relay-tier policy that honest nodes may legitimately disagree on, and
//! treating them as consensus is precisely the error that would fracture the
//! network along configuration lines.

/// Why a rejection happened, in the only terms a drop decision may consult.
///
/// The discriminants are the C ABI (`SHEKYL_DROP_VERDICT_*` in
/// `src/shekyl/shekyl_ffi.h`). C++ **assigns** these and never interprets
/// them; the rule is [`DropVerdict::severs`], which lives here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DropVerdict {
    /// Nothing classified this rejection.
    ///
    /// This is the zero value, so a `tx_verification_context` that is
    /// value-initialised — and any rejection path added later that does not
    /// classify itself — lands here. **It does not sever.** That is the
    /// guarantee the whole design rests on: a new failure arm is safe by
    /// construction, and becomes droppable only when someone affirmatively
    /// says it describes the sender's input.
    #[default]
    Unclassified = 0,

    /// The rejection describes **our own state**, or a rule that is **ours**
    /// rather than everyone's.
    ///
    /// Both halves of PWD-B7's test land here, and they are distinct failures
    /// that happen to share a verdict: a fee below *our* floor or a key image
    /// spent in *our* view describes our state, while an oversized `tx_extra`
    /// or a non-zero unlock time describes the input but fails a rule the
    /// sender may legitimately not share. Severing for either punishes an
    /// honest peer for divergence.
    PolicyOrState = 1,

    /// **We** failed — a broken invariant, an exception, a resource we could
    /// not obtain.
    ///
    /// The sender is not answerable for this and must not be charged for it.
    /// It is separated from [`Self::PolicyOrState`] because the two want
    /// different *logs*, not different drop behaviour: a policy rejection is
    /// routine, an internal failure is a bug and should be loud. See
    /// [`DropVerdict::is_internal_failure`].
    InternalFailure = 2,

    /// The rejection describes the **input**, against a **universal** rule.
    ///
    /// Malformed bytes, a structurally invalid transaction, a consensus rule
    /// the transaction cannot satisfy anywhere. The sender chose to send those
    /// bytes and every honest node would reject them identically, so the
    /// offense is attributable. **This is the only verdict that severs.**
    AttributableForm = 3,
}

impl DropVerdict {
    /// Reads a verdict byte that crossed the FFI boundary.
    ///
    /// Any byte this crate does not recognise resolves to
    /// [`Self::Unclassified`] rather than panicking or being rejected: the
    /// caller is a drop decision on a live connection, and the safe answer to
    /// "I do not understand this" is "do not sever".
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::PolicyOrState,
            2 => Self::InternalFailure,
            3 => Self::AttributableForm,
            _ => Self::Unclassified,
        }
    }

    /// The verdict as its ABI byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// **The rule.** May a rejection carrying this verdict sever the
    /// connection that delivered it?
    ///
    /// Exactly one verdict says yes. Every other value of the byte — the
    /// classified no-drop arms, the unset arm, and anything unrecognised —
    /// says no.
    #[must_use]
    pub const fn severs(self) -> bool {
        matches!(self, Self::AttributableForm)
    }

    /// Should this rejection be logged as a defect of ours rather than a
    /// routine refusal?
    ///
    /// A second predicate rather than a disposition returned to C++: the
    /// caller asks the two questions it actually has, and never acquires the
    /// ability to branch on the verdict itself.
    #[must_use]
    pub const fn is_internal_failure(self) -> bool {
        matches!(self, Self::InternalFailure)
    }

    /// Folds a newly observed classification into one already recorded.
    ///
    /// **A no-drop verdict, once recorded, cannot be promoted back to
    /// droppable.** The result severs iff at least one classification was
    /// recorded and every one of them severs. Between two no-drop verdicts
    /// the first is kept; they agree on the drop decision and differ only
    /// in how loudly they log, and the earlier one is the more specific.
    ///
    /// This is the algebra behind [`Self::classify_in_place`]. C++ never
    /// assigns the ABI byte; it writes through that method so a second
    /// classification on the same slot cannot resurrect a drop.
    #[must_use]
    pub const fn combine(self, incoming: Self) -> Self {
        match (self, incoming) {
            (current, Self::Unclassified) => current,
            (Self::Unclassified | Self::AttributableForm, incoming) => incoming,
            (current, _) => current,
        }
    }

    /// Folds `incoming` into an ABI slot. This is the only write path the
    /// C++ side is supposed to use.
    pub const fn classify_in_place(slot: &mut u8, incoming: Self) {
        *slot = Self::from_byte(*slot).combine(incoming).to_byte();
    }
}

#[cfg(test)]
mod tests {
    use super::DropVerdict;

    /// The rule, over the entire domain of the ABI byte rather than over the
    /// four names — an unrecognised byte is the case a name-based test cannot
    /// reach, and it is exactly what a future writer will produce.
    #[test]
    fn exactly_one_byte_of_two_hundred_fifty_six_severs() {
        let severing: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|byte| DropVerdict::from_byte(*byte).severs())
            .collect();
        assert_eq!(severing, vec![DropVerdict::AttributableForm.to_byte()]);
    }

    /// The zero value is the one a value-initialised C++ struct produces, and
    /// the one an unclassified new failure arm inherits.
    #[test]
    fn the_zero_byte_is_unclassified_and_does_not_sever() {
        assert_eq!(DropVerdict::from_byte(0), DropVerdict::Unclassified);
        assert_eq!(DropVerdict::default(), DropVerdict::Unclassified);
        assert_eq!(DropVerdict::Unclassified.to_byte(), 0);
        assert!(!DropVerdict::Unclassified.severs());
    }

    /// Round-tripping pins each discriminant to its ABI byte, which the
    /// hand-written C header restates.
    #[test]
    fn every_verdict_round_trips_through_its_abi_byte() {
        for verdict in [
            DropVerdict::Unclassified,
            DropVerdict::PolicyOrState,
            DropVerdict::InternalFailure,
            DropVerdict::AttributableForm,
        ] {
            assert_eq!(DropVerdict::from_byte(verdict.to_byte()), verdict);
        }
        assert_eq!(DropVerdict::PolicyOrState.to_byte(), 1);
        assert_eq!(DropVerdict::InternalFailure.to_byte(), 2);
        assert_eq!(DropVerdict::AttributableForm.to_byte(), 3);
    }

    /// The property `combine` exists for, stated over every ordered pair: a
    /// fold severs only if something was recorded and everything recorded
    /// severs.
    #[test]
    fn combining_severs_only_when_every_recorded_classification_severs() {
        let all = [
            DropVerdict::Unclassified,
            DropVerdict::PolicyOrState,
            DropVerdict::InternalFailure,
            DropVerdict::AttributableForm,
        ];
        for current in all {
            for incoming in all {
                let recorded: Vec<DropVerdict> = [current, incoming]
                    .into_iter()
                    .filter(|verdict| *verdict != DropVerdict::Unclassified)
                    .collect();
                let expected =
                    !recorded.is_empty() && recorded.iter().all(|verdict| verdict.severs());
                assert_eq!(
                    current.combine(incoming).severs(),
                    expected,
                    "combine({current:?}, {incoming:?})"
                );
            }
        }
    }

    /// A later form classification cannot resurrect a drop once a no-drop
    /// reading has been recorded on the same slot.
    #[test]
    fn a_coarse_form_verdict_cannot_overwrite_a_precise_state_verdict() {
        let mut slot = DropVerdict::Unclassified.to_byte();
        DropVerdict::classify_in_place(&mut slot, DropVerdict::PolicyOrState);
        DropVerdict::classify_in_place(&mut slot, DropVerdict::AttributableForm);
        assert_eq!(DropVerdict::from_byte(slot), DropVerdict::PolicyOrState);
        assert!(!DropVerdict::from_byte(slot).severs());
    }

    /// The opposite order, which is the one that actually occurs at
    /// `tx_pool.cpp` when the fold is written defensively at both sites.
    #[test]
    fn an_internal_failure_survives_a_later_form_verdict() {
        let folded = DropVerdict::InternalFailure.combine(DropVerdict::AttributableForm);
        assert_eq!(folded, DropVerdict::InternalFailure);
        assert!(!folded.severs());
        assert!(folded.is_internal_failure());
    }

    /// `is_internal_failure` selects one arm and does not shadow `severs`.
    #[test]
    fn only_the_internal_arm_is_loud_and_it_never_severs() {
        let loud: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|byte| DropVerdict::from_byte(*byte).is_internal_failure())
            .collect();
        assert_eq!(loud, vec![DropVerdict::InternalFailure.to_byte()]);
        assert!(!DropVerdict::InternalFailure.severs());
    }
}
