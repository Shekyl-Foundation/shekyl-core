// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

//! The settlement-outcome row — `SO-D2`'s value half.
//!
//! [`ARCHIVAL_SETTLEMENT_WRITER.md`](../../docs/design/ARCHIVAL_SETTLEMENT_WRITER.md)
//! `SO-D2` pins a 48-byte key and a 3-byte value. **The key is not declared
//! here and has no type of its own**: it is byte-identical to
//! `ArchivalServeCreditKey` (`src/blockchain_db/shekyl_types.h`,
//! `P_id[32] ‖ BE(shard_id) ‖ BE(settlement_epoch)`), and the whole point of
//! that choice is that one key probes both tables. A second 48-byte key class
//! would be a twin to keep in sync, not a boundary.
//!
//! This module owns the value, because the value carries an invariant.
//!
//! # The duplicate is deliberate, so it is made unrepresentable rather than asserted
//!
//! `outcome` is derivable from `(passes, issued)` — storing all three
//! duplicates [`crate::settle_epoch`]. `SO-D2` keeps the duplicate on purpose
//! (a consensus verdict must not be re-derived on every read: two readers that
//! re-derive are two readers that can disagree), and specified a **write-side
//! assert** that the stored outcome equals the fold.
//!
//! An assert is the weaker form of that guarantee, so it is not what this
//! module does. [`SettlementRow`] has **no constructor that accepts an
//! outcome**: the only way to obtain one is [`SettlementRow::settle`], which
//! *runs* the fold. A row whose outcome disagrees with its counts is therefore
//! not a row this type can express — there is no path to check, because there
//! is no path. The same reasoning as `EncryptedOutputField` in
//! `shekyl-crypto-pq`: when a guarantee has one enforcing site, spend the type
//! rather than the assertion.
//!
//! [`SettlementRow::decode`] re-runs the fold too, so a row that was corrupted
//! at rest fails to decode instead of being trusted for the byte it happens to
//! carry.

use crate::attestation::{settle_epoch, EpochSettlement, SettleError};

/// Encoded length of a settlement-outcome value: `outcome ‖ passes ‖ issued`.
pub const SETTLEMENT_ROW_LEN: usize = 3;

/// `outcome` byte for [`EpochSettlement::Served`].
pub const OUTCOME_SERVED: u8 = 0x01;
/// `outcome` byte for [`EpochSettlement::Missed`].
pub const OUTCOME_MISSED: u8 = 0x02;
/// `outcome` byte for [`EpochSettlement::NonObservation`].
pub const OUTCOME_NON_OBSERVATION: u8 = 0x03;

/// Why a settlement row could not be built or read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RowError {
    /// The fold refused the counts. Carries [`SettleError`] unchanged.
    #[error("settlement fold refused the counts: {0}")]
    Settle(#[from] SettleError),

    /// `issued == 0` — a pair the urn never reached, which `SO-D1` rules is
    /// **not written at all**.
    ///
    /// The fold answers `NonObservation` for zero issuance, and that answer is
    /// correct *as arithmetic*: nothing was observed. But a stored row with
    /// `issued = 0` would assert "issued, and unreachable" about a pair that
    /// was never issued, and it would break the invariant `SO-D1` exists for —
    /// **absent ⇒ never issued** is a theorem about the writer, and only stays
    /// one while the writer cannot emit this row.
    ///
    /// Refused here, at the row constructor, rather than in `settle_epoch`:
    /// the fold is a pure statement about counts and has other callers; the
    /// ROW is the storage boundary, and it is storage that `SO-D1` rules on.
    #[error(
        "issued is 0: SO-D1 writes a row only for a pair with issued >= 1, so          absence means never-issued; a zero-issued row would make absence          ambiguous and is refused at the boundary rather than stored"
    )]
    IssuedZero,

    /// `issued` does not fit the one byte `SO-D2` allots it.
    ///
    /// Not a truncation: `CHALLENGES_PER_PAIR_PER_EPOCH = 3` and the band
    /// variant that would have produced 4 was rejected, so a count above 255
    /// means the issuing mechanism changed without this encoding changing
    /// with it. That must fail at the write, loudly.
    #[error(
        "issued ({issued}) exceeds the one byte SO-D2 allots it: \
         CHALLENGES_PER_PAIR_PER_EPOCH is 3, so this is a mechanism change \
         that must re-pin the row encoding rather than truncate into it"
    )]
    IssuedOutOfRange {
        /// The out-of-range issued count.
        issued: u32,
    },

    /// A stored value was not [`SETTLEMENT_ROW_LEN`] bytes.
    #[error("settlement row is {got} bytes, expected {SETTLEMENT_ROW_LEN}")]
    BadLength {
        /// Length actually found.
        got: usize,
    },

    /// The first byte is not one of the three live outcome tags.
    ///
    /// `0x00` lands here by construction — `SO-D2` refuses to spend it on a
    /// live value precisely so a zero-filled or partially-written cell is
    /// distinguishable from a settlement, in a table whose entire job is
    /// making absence mean something.
    #[error("unknown settlement outcome tag {tag:#04x} (0x00 is deliberately not a live value)")]
    UnknownOutcome {
        /// The tag byte found.
        tag: u8,
    },

    /// The stored outcome disagrees with the fold over the stored counts.
    #[error(
        "stored outcome {stored:#04x} disagrees with the fold over \
         (passes={passes}, issued={issued}), which yields {derived:#04x}: \
         the row is corrupt, not merely stale"
    )]
    OutcomeDisagrees {
        /// Outcome byte as stored.
        stored: u8,
        /// Outcome byte the fold derives from the stored counts.
        derived: u8,
        /// Stored pass count.
        passes: u8,
        /// Stored issued count.
        issued: u8,
    },
}

/// One settlement-outcome row: `outcome ‖ passes ‖ issued`, three bytes.
///
/// See the module docs for why there is no outcome-taking constructor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SettlementRow([u8; SETTLEMENT_ROW_LEN]);

impl SettlementRow {
    /// Fold `(passes, issued)` into a row.
    ///
    /// This is the only way to construct one, which is what makes the stored
    /// `outcome` incapable of disagreeing with the stored counts.
    ///
    /// # Errors
    ///
    /// [`RowError::Settle`] if the fold refuses the counts (`passes > issued`),
    /// [`RowError::IssuedZero`] if `issued == 0` (`SO-D1`: not written),
    /// [`RowError::IssuedOutOfRange`] if `issued` does not fit one byte.
    pub fn settle(passes: u32, issued: u32) -> Result<Self, RowError> {
        // SO-D1: a pair with no issued challenge is not written. Checked before
        // the fold, because the fold would answer NonObservation and hand back
        // a well-formed row for the one state the table must not contain.
        if issued == 0 {
            return Err(RowError::IssuedZero);
        }
        let settlement = settle_epoch(passes, issued)?;
        // `passes <= issued` is guaranteed by the fold above, so bounding
        // `issued` bounds both. Checking only the larger is not a shortcut
        // that could drift: the fold's refusal is what makes it sound.
        if issued > u32::from(u8::MAX) {
            return Err(RowError::IssuedOutOfRange { issued });
        }
        Ok(Self([
            outcome_tag(settlement),
            u8::try_from(passes).expect("passes <= issued <= u8::MAX, checked above"),
            u8::try_from(issued).expect("issued <= u8::MAX, checked above"),
        ]))
    }

    /// The three stored bytes, for the LMDB value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SETTLEMENT_ROW_LEN] {
        &self.0
    }

    /// Read a stored value back, re-running the fold to reject corruption.
    ///
    /// # Errors
    ///
    /// [`RowError::BadLength`] if `bytes` is not [`SETTLEMENT_ROW_LEN`],
    /// [`RowError::UnknownOutcome`] for a tag outside the three live ones,
    /// [`RowError::IssuedZero`] for a stored `issued == 0` (`SO-D1`: the
    /// writer cannot emit it, so a stored one is corruption),
    /// [`RowError::Settle`] if the stored counts do not fold at all
    /// (`passes > issued`), and [`RowError::OutcomeDisagrees`] if they fold to
    /// an outcome other than the stored tag — the last being the check that
    /// makes the deliberate duplicate self-verifying at rest.
    pub fn decode(bytes: &[u8]) -> Result<Self, RowError> {
        let &[tag, passes, issued] = bytes else {
            return Err(RowError::BadLength { got: bytes.len() });
        };
        // Reject an unknown tag before folding, so a zero-filled cell reports
        // the tag it actually has rather than a disagreement with a fold it
        // never took part in.
        if !matches!(
            tag,
            OUTCOME_SERVED | OUTCOME_MISSED | OUTCOME_NON_OBSERVATION
        ) {
            return Err(RowError::UnknownOutcome { tag });
        }
        // `SO-D1`: the writer cannot emit `issued == 0`, so a stored row that
        // carries it is corruption rather than a settlement. Refused on the
        // read side too, because an invariant enforced only on the way in is
        // one a corrupt cell walks straight past on the way out.
        if issued == 0 {
            return Err(RowError::IssuedZero);
        }
        let derived = outcome_tag(settle_epoch(u32::from(passes), u32::from(issued))?);
        if derived != tag {
            return Err(RowError::OutcomeDisagrees {
                stored: tag,
                derived,
                passes,
                issued,
            });
        }
        Ok(Self([tag, passes, issued]))
    }

    /// The settled outcome.
    #[must_use]
    pub const fn outcome(&self) -> EpochSettlement {
        match self.0[0] {
            OUTCOME_SERVED => EpochSettlement::Served,
            OUTCOME_MISSED => EpochSettlement::Missed,
            // Unreachable for a constructed row: both constructors reject any
            // other tag. Mapping rather than panicking keeps this `const`.
            _ => EpochSettlement::NonObservation,
        }
    }

    /// Admission-verified pass records counted for the pair-epoch.
    #[must_use]
    pub const fn passes(&self) -> u8 {
        self.0[1]
    }

    /// Challenges the urn derivation assigned to the pair-epoch.
    ///
    /// Stored rather than recomputed because `ARCHIVAL_CHALLENGE_MECHANISM.md`
    /// §7.1 makes the issued-count histogram an `(m, n)` derivation input under
    /// absolute-2 — this byte is the histogram's source.
    #[must_use]
    pub const fn issued(&self) -> u8 {
        self.0[2]
    }
}

const fn outcome_tag(settlement: EpochSettlement) -> u8 {
    match settlement {
        EpochSettlement::Served => OUTCOME_SERVED,
        EpochSettlement::Missed => OUTCOME_MISSED,
        EpochSettlement::NonObservation => OUTCOME_NON_OBSERVATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CHALLENGES_PER_PAIR_PER_EPOCH;

    /// `SO-D1`'s forcing case, as the round's §10 item 1.
    ///
    /// A drawable pair whose three challenges all expire produces **zero
    /// on-chain artifacts**. A record-driven writer emits nothing, the row is
    /// absent, and absence means non-observation — the pair that failed
    /// completely would settle as the most forgiving outcome. The row this
    /// test asserts is the one only an *enumerating* writer can produce.
    ///
    /// The edit that makes this red is deleting the enumeration: with no
    /// enumeration there is no `(0, 3)` call site at all.
    #[test]
    fn a_pair_that_passes_nothing_settles_missed_not_non_observation() {
        let row = SettlementRow::settle(0, CHALLENGES_PER_PAIR_PER_EPOCH)
            .expect("zero passes over full issuance is a settleable state");

        assert_eq!(
            row.outcome(),
            EpochSettlement::Missed,
            "a fully-issued, fully-failed epoch must settle Missed; NonObservation here \
             is the slash escape SO-D1 exists to close"
        );
        assert_eq!(row.passes(), 0);
        assert_eq!(u32::from(row.issued()), CHALLENGES_PER_PAIR_PER_EPOCH);
        assert_ne!(row.as_bytes()[0], OUTCOME_NON_OBSERVATION);
    }

    /// `SO-D2`: the stored outcome cannot disagree with the stored counts,
    /// because no constructor accepts an outcome. This asserts the property
    /// over the whole reachable input space rather than at one point.
    #[test]
    fn stored_outcome_always_equals_the_fold_over_stored_counts() {
        // SO-D1: issued >= 1 is the writable space; 0 is refused, not stored.
        for issued in 1..=8u32 {
            for passes in 0..=issued {
                let row = SettlementRow::settle(passes, issued).expect("passes <= issued");
                let refolded = settle_epoch(u32::from(row.passes()), u32::from(row.issued()))
                    .expect("round-tripped counts stay foldable");
                assert_eq!(
                    row.outcome(),
                    refolded,
                    "row ({passes}, {issued}) stores an outcome the fold does not derive"
                );
            }
        }
    }

    /// Under absolute-2 a pair the urn could not reach twice is not a pair
    /// that failed — and it gets a **row**, not an absence. That is the
    /// auditability half of `SO-D1`: the capped regime is where the teeth
    /// degrade, and silent degradation is unmeasured degradation.
    #[test]
    fn under_issuance_settles_non_observation_and_is_still_a_row() {
        // `issued == 1` is the under-issuance case: a row, not an absence.
        for passes in 0..=1u32 {
            let row = SettlementRow::settle(passes, 1).expect("passes <= issued");
            assert_eq!(row.outcome(), EpochSettlement::NonObservation);
            assert_eq!(
                u32::from(row.issued()),
                1,
                "the issued count survives storage"
            );
        }

        // And the boundary the case sits against: ZERO issuance is not a row
        // at all. Asserted here, beside its neighbour, because the pair is the
        // ruling — `SO-D1` distinguishes "issued but unreachable" (a written
        // NonObservation) from "never issued" (an absence), and a test that
        // covered only the first would leave the two synonymous again.
        assert!(
            matches!(SettlementRow::settle(0, 0), Err(RowError::IssuedZero)),
            "a zero-issued pair must be refused, not stored as NonObservation"
        );
        assert!(
            matches!(
                SettlementRow::decode(&[OUTCOME_NON_OBSERVATION, 0, 0]),
                Err(RowError::IssuedZero)
            ),
            "a stored zero-issued row must be refused on read as well as on write"
        );
    }

    #[test]
    fn round_trips_through_bytes() {
        for issued in 1..=5u32 {
            for passes in 0..=issued {
                let row = SettlementRow::settle(passes, issued).expect("passes <= issued");
                let back = SettlementRow::decode(row.as_bytes()).expect("own bytes decode");
                assert_eq!(row, back);
            }
        }
    }

    /// A zero-filled or partially-written cell must not read as a settlement.
    /// `SO-D2` refuses `0x00` as a live tag for exactly this reason.
    #[test]
    fn a_zero_filled_cell_is_not_a_settlement() {
        assert_eq!(
            SettlementRow::decode(&[0x00, 0x00, 0x00]),
            Err(RowError::UnknownOutcome { tag: 0x00 })
        );
    }

    #[test]
    fn wrong_length_is_refused_rather_than_padded() {
        assert_eq!(
            SettlementRow::decode(&[OUTCOME_SERVED, 2]),
            Err(RowError::BadLength { got: 2 })
        );
        assert_eq!(
            SettlementRow::decode(&[OUTCOME_SERVED, 2, 3, 0]),
            Err(RowError::BadLength { got: 4 })
        );
    }

    /// The check that makes the deliberate duplicate self-verifying: a row
    /// whose outcome byte was flipped at rest fails to decode rather than
    /// being trusted for the byte it happens to carry.
    #[test]
    fn a_flipped_outcome_byte_fails_to_decode() {
        let row = SettlementRow::settle(0, 3).expect("settleable");
        assert_eq!(row.as_bytes()[0], OUTCOME_MISSED);

        let mut corrupted = *row.as_bytes();
        corrupted[0] = OUTCOME_SERVED;

        assert_eq!(
            SettlementRow::decode(&corrupted),
            Err(RowError::OutcomeDisagrees {
                stored: OUTCOME_SERVED,
                derived: OUTCOME_MISSED,
                passes: 0,
                issued: 3,
            })
        );
    }

    /// A desynced accounting input is a typed refusal, never a clamp — the
    /// posture `SettleError` sets, preserved through the row constructor.
    #[test]
    fn more_passes_than_issued_is_refused_not_clamped() {
        assert_eq!(
            SettlementRow::settle(3, 2),
            Err(RowError::Settle(SettleError::MorePassesThanIssued {
                passes: 3,
                issued: 2
            }))
        );
    }

    /// `issued > 255` is a mechanism change, not a value to truncate.
    #[test]
    fn issued_beyond_one_byte_is_refused_rather_than_truncated() {
        assert_eq!(
            SettlementRow::settle(0, 256),
            Err(RowError::IssuedOutOfRange { issued: 256 })
        );
        // 255 still fits, so the boundary is exact rather than defensive.
        assert!(SettlementRow::settle(0, 255).is_ok());
    }

    /// The three live tags are distinct and none is `0x00`.
    #[test]
    fn outcome_tags_are_distinct_and_never_zero() {
        let tags = [OUTCOME_SERVED, OUTCOME_MISSED, OUTCOME_NON_OBSERVATION];
        for (i, a) in tags.iter().enumerate() {
            assert_ne!(*a, 0x00, "0x00 must stay reserved for 'not a settlement'");
            for b in &tags[i + 1..] {
                assert_ne!(a, b, "outcome tags must be distinguishable");
            }
        }
    }
}
