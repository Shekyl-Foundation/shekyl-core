// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One outcome of attempting to ingest a block — the type that replaces
//! `block_verification_context`'s bag of independent bools.
//!
//! # Why a discriminant
//!
//! The inherited struct answered "what happened" with six flags that were
//! never exclusive. `m_added_to_main_chain` and `m_verifivation_failed`
//! were not complements: both-false was a real third class (orphan, alt
//! chain stored without a switch, prune-watermark refused switch). P2P
//! then dropped on the *set-ness* of the misspelled failed flag, so a
//! writer that described *our* state with that flag partitioned us from
//! honest peers advertising a heavier chain.
//!
//! PWD-B7 typed the transaction twin (`DropVerdict` on `tvc`). This type
//! is the block twin: one arm per setter, predicates for the questions
//! P2P actually asks, and the drop decision still living on a separate
//! [`crate::DropVerdict`] slot so a rejected block does not sever unless
//! the rejection is attributable to the sender.
//!
//! # What C++ may ask
//!
//! C++ **assigns** these bytes through [`BlockIngest::record_in_place`]
//! (non-reject arms) or the paired [`BlockIngest::write_reject_form`]
//! family (reject arms) and never switches on them. The questions it is
//! allowed to ask of this type are the predicates below. What P2P should
//! *do* with the two slots is [`crate::BlockAnnounceAction`] /
//! [`crate::BlockSyncAction`], not a C++ if-else over these predicates.
//! An unrecognised byte is [`Self::Unclassified`]: not added, not
//! rejected, not missing-txs, not orphaned — and, because drop is a
//! different slot, not a reason to sever.

use crate::DropVerdict;

/// What happened when we tried to take a block.
///
/// Discriminants are the C ABI (`SHEKYL_BLOCK_INGEST_*` in
/// `src/shekyl/shekyl_ffi.h`). Zero is the value-initialised C++ struct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum BlockIngest {
    /// Nothing recorded. Value-init, and any new arm that forgets to
    /// classify itself. **Not a rejection.** P2P must not drop on it;
    /// drop is [`DropVerdict`]'s question, and that slot's zero does not
    /// sever either.
    #[default]
    Unclassified = 0,

    /// The block is now the main-chain tip (or was promoted onto it).
    AddedToMainChain = 1,

    /// We already have this hash. Not invalid; not new.
    AlreadyExists = 2,

    /// Parent unknown. Not invalid; the sync path re-requests history.
    Orphaned = 3,

    /// Fluffy / compact payload was incomplete. PoW already passed
    /// (the check sits before this arm), so re-request the missing
    /// txs rather than dropping. Distinct from [`Self::Rejected`]:
    /// the inherited code set *both* `m_verifivation_failed` and
    /// `m_missing_txs`, and P2P then special-cased the latter.
    MissingTxs = 4,

    /// Fork-choice wanted a switch; the prune watermark refused it.
    /// The block is kept as an alternative. Local retention, not
    /// invalidity — setting the inherited failed flag here isolated
    /// a degraded node onto its own fork.
    DegradedKeep = 5,

    /// Stored on an alternative chain; not switched. Success, no relay.
    AltStored = 6,

    /// Verification refused the block. Whether the peer is dropped is
    /// [`DropVerdict`] on the same context, not this arm.
    Rejected = 7,

    /// Refused because the PoW does not meet the target. Same drop
    /// question as [`Self::Rejected`]; the extra score weight is the
    /// only operational difference (`P2P_IP_FAILS_BEFORE_BLOCK`).
    /// Unrepresentable together with [`Self::MissingTxs`]: PoW runs
    /// first.
    RejectedBadPow = 8,
}

impl BlockIngest {
    /// Reads an outcome byte that crossed the FFI boundary.
    ///
    /// Any unrecognised value is [`Self::Unclassified`]: the safe
    /// answer to "I do not understand this" is that nothing happened
    /// that P2P should act on.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::AddedToMainChain,
            2 => Self::AlreadyExists,
            3 => Self::Orphaned,
            4 => Self::MissingTxs,
            5 => Self::DegradedKeep,
            6 => Self::AltStored,
            7 => Self::Rejected,
            8 => Self::RejectedBadPow,
            _ => Self::Unclassified,
        }
    }

    /// The outcome as its ABI byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Did this block land on the main chain?
    #[must_use]
    pub const fn is_added(self) -> bool {
        matches!(self, Self::AddedToMainChain)
    }

    /// Did we already have this hash?
    #[must_use]
    pub const fn already_exists(self) -> bool {
        matches!(self, Self::AlreadyExists)
    }

    /// Is the parent unknown?
    #[must_use]
    pub const fn is_orphaned(self) -> bool {
        matches!(self, Self::Orphaned)
    }

    /// Should P2P re-request missing compact-block txs rather than drop?
    #[must_use]
    pub const fn missing_txs(self) -> bool {
        matches!(self, Self::MissingTxs)
    }

    /// Was the block refused? Covers both ordinary rejection and the
    /// bad-PoW arm. Drop is still [`DropVerdict::severs`], not this.
    #[must_use]
    pub const fn is_rejected(self) -> bool {
        matches!(self, Self::Rejected | Self::RejectedBadPow)
    }

    /// Should a drop (if any) carry the heavier PoW-DoS score?
    #[must_use]
    pub const fn is_bad_pow(self) -> bool {
        matches!(self, Self::RejectedBadPow)
    }

    /// Folds a newly recorded outcome into one already stored.
    ///
    /// **First writer wins.** `Unclassified` yields to anything; a
    /// recorded arm is not overwritten. The inherited flags could be
    /// set independently and disagree; this algebra makes disagreement
    /// unrepresentable after the first classification.
    #[must_use]
    pub const fn combine(self, incoming: Self) -> Self {
        match (self, incoming) {
            (current, Self::Unclassified) => current,
            (Self::Unclassified, incoming) => incoming,
            (current, _) => current,
        }
    }

    /// Folds `incoming` into an ABI slot. The C++ write path for
    /// non-reject arms (added, orphaned, missing-txs, …).
    pub const fn record_in_place(slot: &mut u8, incoming: Self) {
        *slot = Self::from_byte(*slot).combine(incoming).to_byte();
    }

    /// Record a consensus/universal refusal and classify the drop as
    /// attributable form. The pairing lives here so C++ cannot write one
    /// slot and forget the other.
    pub const fn write_reject_form(outcome: &mut u8, drop: &mut u8) {
        Self::record_in_place(outcome, Self::Rejected);
        DropVerdict::classify_in_place(drop, DropVerdict::AttributableForm);
    }

    /// Record a refusal that describes our state or a local policy.
    pub const fn write_reject_state(outcome: &mut u8, drop: &mut u8) {
        Self::record_in_place(outcome, Self::Rejected);
        DropVerdict::classify_in_place(drop, DropVerdict::PolicyOrState);
    }

    /// Record a refusal that is a defect of ours.
    pub const fn write_reject_internal(outcome: &mut u8, drop: &mut u8) {
        Self::record_in_place(outcome, Self::Rejected);
        DropVerdict::classify_in_place(drop, DropVerdict::InternalFailure);
    }

    /// Record a PoW-below-target refusal. Drop is still form: the sender
    /// chose these bytes, and every honest node would refuse them.
    pub const fn write_reject_bad_pow(outcome: &mut u8, drop: &mut u8) {
        Self::record_in_place(outcome, Self::RejectedBadPow);
        DropVerdict::classify_in_place(drop, DropVerdict::AttributableForm);
    }

    /// Record a refusal whose drop classification already happened on
    /// the tx path. Fold the incoming verdict; do not re-interpret it.
    pub const fn write_reject_with_drop(outcome: &mut u8, drop: &mut u8, incoming: DropVerdict) {
        Self::record_in_place(outcome, Self::Rejected);
        DropVerdict::classify_in_place(drop, incoming);
    }
}

/// Documented pairing: a rejected block still does not sever unless the
/// drop slot says so. Kept next to the type so the two slots cannot be
/// read as one question.
#[cfg(test)]
#[must_use]
const fn rejected_severs(outcome: BlockIngest, drop: DropVerdict) -> bool {
    outcome.is_rejected() && drop.severs()
}

#[cfg(test)]
mod tests {
    use super::{rejected_severs, BlockIngest};
    use crate::DropVerdict;

    #[test]
    fn the_zero_byte_is_unclassified_and_answers_no_to_every_predicate() {
        let u = BlockIngest::from_byte(0);
        assert_eq!(u, BlockIngest::Unclassified);
        assert_eq!(BlockIngest::default(), BlockIngest::Unclassified);
        assert_eq!(BlockIngest::Unclassified.to_byte(), 0);
        assert!(!u.is_added());
        assert!(!u.already_exists());
        assert!(!u.is_orphaned());
        assert!(!u.missing_txs());
        assert!(!u.is_rejected());
        assert!(!u.is_bad_pow());
    }

    #[test]
    fn every_arm_round_trips_and_unrecognised_bytes_are_unclassified() {
        for arm in [
            BlockIngest::Unclassified,
            BlockIngest::AddedToMainChain,
            BlockIngest::AlreadyExists,
            BlockIngest::Orphaned,
            BlockIngest::MissingTxs,
            BlockIngest::DegradedKeep,
            BlockIngest::AltStored,
            BlockIngest::Rejected,
            BlockIngest::RejectedBadPow,
        ] {
            assert_eq!(BlockIngest::from_byte(arm.to_byte()), arm);
        }
        for byte in 9u8..=u8::MAX {
            assert_eq!(BlockIngest::from_byte(byte), BlockIngest::Unclassified);
        }
    }

    #[test]
    fn predicates_select_exactly_the_arms_they_name() {
        let added: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).is_added())
            .collect();
        assert_eq!(added, vec![BlockIngest::AddedToMainChain.to_byte()]);

        let exists: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).already_exists())
            .collect();
        assert_eq!(exists, vec![BlockIngest::AlreadyExists.to_byte()]);

        let orphan: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).is_orphaned())
            .collect();
        assert_eq!(orphan, vec![BlockIngest::Orphaned.to_byte()]);

        let missing: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).missing_txs())
            .collect();
        assert_eq!(missing, vec![BlockIngest::MissingTxs.to_byte()]);

        let rejected: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).is_rejected())
            .collect();
        assert_eq!(
            rejected,
            vec![
                BlockIngest::Rejected.to_byte(),
                BlockIngest::RejectedBadPow.to_byte(),
            ]
        );

        let bad_pow: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|b| BlockIngest::from_byte(*b).is_bad_pow())
            .collect();
        assert_eq!(bad_pow, vec![BlockIngest::RejectedBadPow.to_byte()]);
    }

    #[test]
    fn first_writer_wins_and_unclassified_never_overwrites() {
        let mut slot = BlockIngest::Unclassified.to_byte();
        BlockIngest::record_in_place(&mut slot, BlockIngest::Rejected);
        BlockIngest::record_in_place(&mut slot, BlockIngest::AddedToMainChain);
        assert_eq!(BlockIngest::from_byte(slot), BlockIngest::Rejected);

        let mut other = BlockIngest::AddedToMainChain.to_byte();
        BlockIngest::record_in_place(&mut other, BlockIngest::Unclassified);
        assert_eq!(BlockIngest::from_byte(other), BlockIngest::AddedToMainChain);
    }

    #[test]
    fn missing_txs_is_not_a_rejection_and_bad_pow_is() {
        assert!(!BlockIngest::MissingTxs.is_rejected());
        assert!(BlockIngest::RejectedBadPow.is_rejected());
        assert!(BlockIngest::RejectedBadPow.is_bad_pow());
        assert!(!BlockIngest::Rejected.is_bad_pow());
    }

    #[test]
    fn a_rejected_block_does_not_sever_unless_the_drop_slot_says_so() {
        assert!(!rejected_severs(
            BlockIngest::Rejected,
            DropVerdict::Unclassified
        ));
        assert!(!rejected_severs(
            BlockIngest::Rejected,
            DropVerdict::InternalFailure
        ));
        assert!(rejected_severs(
            BlockIngest::RejectedBadPow,
            DropVerdict::AttributableForm
        ));
        assert!(!rejected_severs(
            BlockIngest::AddedToMainChain,
            DropVerdict::AttributableForm
        ));
    }

    #[test]
    fn both_false_arms_are_named_and_are_not_rejections() {
        for arm in [
            BlockIngest::DegradedKeep,
            BlockIngest::AltStored,
            BlockIngest::Orphaned,
            BlockIngest::AlreadyExists,
        ] {
            assert!(!arm.is_rejected(), "{arm:?}");
            assert!(!arm.is_added(), "{arm:?}");
        }
    }

    #[test]
    fn write_reject_pairs_the_outcome_and_the_drop_slot() {
        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        BlockIngest::write_reject_form(&mut outcome, &mut drop);
        assert_eq!(BlockIngest::from_byte(outcome), BlockIngest::Rejected);
        assert!(DropVerdict::from_byte(drop).severs());

        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        BlockIngest::write_reject_internal(&mut outcome, &mut drop);
        assert!(BlockIngest::from_byte(outcome).is_rejected());
        assert!(!DropVerdict::from_byte(drop).severs());
        assert!(DropVerdict::from_byte(drop).is_internal_failure());

        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        BlockIngest::write_reject_state(&mut outcome, &mut drop);
        assert!(BlockIngest::from_byte(outcome).is_rejected());
        assert_eq!(DropVerdict::from_byte(drop), DropVerdict::PolicyOrState);

        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        BlockIngest::write_reject_bad_pow(&mut outcome, &mut drop);
        assert!(BlockIngest::from_byte(outcome).is_bad_pow());
        assert!(DropVerdict::from_byte(drop).severs());
    }

    #[test]
    fn write_reject_with_drop_folds_the_tx_path_verdict() {
        let mut outcome = BlockIngest::Unclassified.to_byte();
        let mut drop = DropVerdict::Unclassified.to_byte();
        BlockIngest::write_reject_with_drop(&mut outcome, &mut drop, DropVerdict::InternalFailure);
        assert!(BlockIngest::from_byte(outcome).is_rejected());
        assert!(!DropVerdict::from_byte(drop).severs());

        BlockIngest::write_reject_with_drop(&mut outcome, &mut drop, DropVerdict::AttributableForm);
        assert!(!DropVerdict::from_byte(drop).severs());
    }
}
