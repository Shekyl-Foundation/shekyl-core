// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement's stored facts: a pair's outcome for an epoch, the draws
//! issued to it, and the digest that guards them.
//!
//! Design: `docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.3 (the row) and
//! §10 (the issued-draw index); `docs/design/ARCHIVAL_SETTLEMENT_WRITER.md`
//! `SO-D2` (the row's bytes) and §14 (`SO-D10`: the pass fact's home).
//!
//! These are state-shaped: the validator derives them, the store holds
//! them, and both name them through this crate. The hashes that select the
//! counted draws and form a digest term are transforms and live in
//! `shekyl-archival-retention`.

use crate::{BlockHeight, PCanonicalId, ShardId};

/// Draws counted for a pair at settlement. A pair with fewer issued draws
/// than this was not observed in the epoch.
pub const COUNTED_DRAWS: usize = COUNTED as usize;

/// Passes among the counted draws that settle the epoch Served.
pub const SERVE_THRESHOLD_PASSES: u8 = 2;

/// [`COUNTED_DRAWS`] in the width the row's bytes compare it at: the one
/// place the number is written.
const COUNTED: u8 = 3;

// The threshold is reachable, and it is a strict majority of the counted
// draws: one pass cannot serve an epoch and no tie exists.
const _: () = assert!(SERVE_THRESHOLD_PASSES <= COUNTED);
const _: () = assert!(2 * SERVE_THRESHOLD_PASSES > COUNTED);

/// Width of a stored [`SettlementRow`].
pub const SETTLEMENT_ROW_LEN: usize = 3;

/// Width of an [`IssuedDigest`].
pub const ISSUED_DIGEST_LEN: usize = 32;

/// What one epoch settled for one pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettlementOutcome {
    /// At least [`SERVE_THRESHOLD_PASSES`] of the counted draws have a pass.
    Served,
    /// The pair was observed and fewer have one. An observation in the
    /// failure window.
    Missed,
    /// Fewer than [`COUNTED_DRAWS`] draws were issued to the pair. Not an
    /// observation: neither a pass nor a miss.
    NonObservation,
}

impl SettlementOutcome {
    const fn tag(self) -> u8 {
        match self {
            Self::Served => 0x01,
            Self::Missed => 0x02,
            Self::NonObservation => 0x03,
        }
    }

    /// The outcome of `passes` among the counted draws of a pair with
    /// `issued` issued draws. One definition, used to build a row and to
    /// check one read back.
    const fn of(passes: u8, issued: u8) -> Self {
        if issued < COUNTED {
            Self::NonObservation
        } else if passes >= SERVE_THRESHOLD_PASSES {
            Self::Served
        } else {
            Self::Missed
        }
    }
}

/// Why a [`SettlementRow`] cannot be formed or is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementRowError {
    /// No draw was issued. Such a pair has no row: absence is the record.
    NothingIssued,
    /// More passes than draws were counted. The writer selects at most
    /// [`COUNTED_DRAWS`], and none when fewer were issued.
    MorePassesThanCounted {
        /// Passes claimed.
        passes: u8,
        /// Draws that could have been counted.
        counted: u8,
    },
    /// Stored bytes of the wrong length.
    BadLength {
        /// Bytes found.
        found: usize,
    },
    /// A first byte that names no outcome. `0x00` is deliberately not one:
    /// it is what a zero-filled cell looks like.
    UnknownOutcome {
        /// The byte found.
        tag: u8,
    },
    /// The stored outcome is not the one its own counts give.
    OutcomeDisagrees,
}

impl core::fmt::Display for SettlementRowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NothingIssued => f.write_str("no draw was issued; such a pair has no row"),
            Self::MorePassesThanCounted { passes, counted } => {
                write!(f, "{passes} passes among {counted} counted draws")
            }
            Self::BadLength { found } => {
                write!(f, "{found} bytes, a row is {SETTLEMENT_ROW_LEN}")
            }
            Self::UnknownOutcome { tag } => write!(f, "outcome byte {tag:#04x} names no outcome"),
            Self::OutcomeDisagrees => f.write_str("the stored outcome is not what the counts give"),
        }
    }
}

/// One pair's settlement for one epoch: `outcome ‖ passes ‖ issued`.
///
/// `passes` is how many of the counted draws have a pass, 0 to
/// [`COUNTED_DRAWS`]; a pair below the floor has no counted draw, so its
/// `passes` is 0 whatever its issued draws recorded. That is tighter than
/// the `passes ≤ issued` the settlement walk halts on (spec §9.5, check 3)
/// and implies it. `issued` is how many draws were issued to the pair,
/// saturating at 255: the byte has only to say "at least three", and the
/// list of draws is the selection's operand, not this count.
///
/// The outcome is stored and not re-derived at each read, because the
/// threshold is a consensus rule and two readers must not be able to
/// disagree. What makes the stored copy safe is that this type is the only
/// way to produce the bytes, and it computes the outcome from the counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettlementRow {
    outcome: SettlementOutcome,
    passes: u8,
    issued: u8,
}

impl SettlementRow {
    /// The row for a pair with `issued` issued draws, `passes` of whose
    /// counted draws have a pass.
    ///
    /// # Errors
    ///
    /// [`SettlementRowError::NothingIssued`] for `issued = 0`;
    /// [`SettlementRowError::MorePassesThanCounted`] if `passes` exceeds the
    /// draws that were counted, which is [`COUNTED_DRAWS`] or, below that,
    /// none.
    pub fn settle(passes: u8, issued: usize) -> Result<Self, SettlementRowError> {
        if issued == 0 {
            return Err(SettlementRowError::NothingIssued);
        }
        let issued = u8::try_from(issued).unwrap_or(u8::MAX);
        let counted = if issued < COUNTED { 0 } else { COUNTED };
        if passes > counted {
            return Err(SettlementRowError::MorePassesThanCounted { passes, counted });
        }
        Ok(Self {
            outcome: SettlementOutcome::of(passes, issued),
            passes,
            issued,
        })
    }

    /// The stored bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; SETTLEMENT_ROW_LEN] {
        [self.outcome.tag(), self.passes, self.issued]
    }

    /// A row read back.
    ///
    /// # Errors
    ///
    /// Any [`SettlementRowError`]: the bytes must be exactly the ones
    /// [`Self::settle`] would have produced.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SettlementRowError> {
        let &[tag, passes, issued] = bytes else {
            return Err(SettlementRowError::BadLength { found: bytes.len() });
        };
        let stored = match tag {
            0x01 => SettlementOutcome::Served,
            0x02 => SettlementOutcome::Missed,
            0x03 => SettlementOutcome::NonObservation,
            tag => return Err(SettlementRowError::UnknownOutcome { tag }),
        };
        let row = Self::settle(passes, usize::from(issued))?;
        if row.outcome != stored {
            return Err(SettlementRowError::OutcomeDisagrees);
        }
        Ok(row)
    }

    /// What the epoch settled.
    #[must_use]
    pub const fn outcome(self) -> SettlementOutcome {
        self.outcome
    }

    /// Passes among the counted draws.
    #[must_use]
    pub const fn passes(self) -> u8 {
        self.passes
    }

    /// Draws issued to the pair, saturated at 255.
    #[must_use]
    pub const fn issued(self) -> u8 {
        self.issued
    }
}

/// What the index holds for one issued draw.
///
/// The draw is named by its key: the pair, the epoch, the issuing block
/// and the draw's index in that block. This is what is recorded about it.
///
/// **The pass fact lives here and nowhere else** (`SO-D10c`). Whatever
/// admits the draw's pass record sets it; settlement reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IssuedDraw {
    /// The block that first admitted the issuing block's seed. A draw is
    /// visible to the count rule at any height above this one.
    pub revealed_at: BlockHeight,
    /// Whether a pass record for this draw has been admitted.
    pub passed: bool,
}

/// One row of an epoch's issued-draw index: which draw, and what is
/// recorded about it. The epoch is the read's operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IndexedDraw {
    /// Whose draw.
    pub persona: PCanonicalId,
    /// Which shard it asks for.
    pub shard: ShardId,
    /// The block that issued it.
    pub issuing_height: BlockHeight,
    /// Its index among that block's draws.
    pub draw: u32,
    /// What the index holds for it.
    pub state: IssuedDraw,
}

/// The running digest of one epoch's issued draws: the sum of their terms
/// as 256-bit little-endian integers, modulo `2^256`.
///
/// It starts at [`IssuedDigest::ZERO`]. A sum does not depend on order, so
/// admission can fold draws as blocks reveal them and settlement can fold
/// them pair by pair. It covers **issuance only**: a draw's pass is set
/// later and is not part of its term.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IssuedDigest([u8; ISSUED_DIGEST_LEN]);

impl IssuedDigest {
    /// The digest of no draws.
    pub const ZERO: Self = Self([0; ISSUED_DIGEST_LEN]);

    /// The digest a store holds.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ISSUED_DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes a store holds.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ISSUED_DIGEST_LEN] {
        &self.0
    }

    /// Add one draw's term.
    pub fn fold(&mut self, term: &[u8; ISSUED_DIGEST_LEN]) {
        let mut carry = 0u16;
        for (acc, add) in self.0.iter_mut().zip(term) {
            let sum = u16::from(*acc) + u16::from(*add) + carry;
            *acc = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        // The carry out of the top byte is the reduction modulo 2^256.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_is_two_of_three_and_fewer_than_three_issued_is_not_observed() {
        use SettlementOutcome::{Missed, NonObservation, Served};
        // Fewer than three issued: nothing is counted, whatever happened.
        for issued in 1..COUNTED_DRAWS {
            assert_eq!(
                SettlementRow::settle(0, issued).map(SettlementRow::outcome),
                Ok(NonObservation)
            );
        }
        for issued in [3usize, 4, 9, 255, 256, 100_000] {
            let outcome =
                |passes| SettlementRow::settle(passes, issued).map(SettlementRow::outcome);
            assert_eq!(outcome(0), Ok(Missed));
            assert_eq!(outcome(1), Ok(Missed));
            assert_eq!(outcome(2), Ok(Served));
            assert_eq!(outcome(3), Ok(Served));
        }
    }

    #[test]
    fn a_pair_with_nothing_issued_has_no_row() {
        assert_eq!(
            SettlementRow::settle(0, 0),
            Err(SettlementRowError::NothingIssued)
        );
        // Not even from stored bytes that claim one.
        assert_eq!(
            SettlementRow::from_bytes(&[0x03, 0, 0]),
            Err(SettlementRowError::NothingIssued)
        );
    }

    #[test]
    fn passes_cannot_exceed_the_draws_that_were_counted() {
        // Three or more issued: three are counted.
        assert_eq!(
            SettlementRow::settle(4, 9),
            Err(SettlementRowError::MorePassesThanCounted {
                passes: 4,
                counted: 3
            })
        );
        // Fewer than three issued: none is counted, so no pass can be.
        assert_eq!(
            SettlementRow::settle(1, 2),
            Err(SettlementRowError::MorePassesThanCounted {
                passes: 1,
                counted: 0
            })
        );
    }

    #[test]
    fn issued_saturates_and_the_bytes_round_trip() {
        let row = SettlementRow::settle(2, 100_000).unwrap();
        assert_eq!(row.issued(), 255);
        assert_eq!(row.to_bytes(), [0x01, 2, 255]);
        for (passes, issued) in [
            (0u8, 1usize),
            (0, 2),
            (0, 3),
            (1, 3),
            (2, 3),
            (3, 7),
            (0, 255),
        ] {
            let row = SettlementRow::settle(passes, issued).unwrap();
            assert_eq!(SettlementRow::from_bytes(&row.to_bytes()), Ok(row));
        }
    }

    #[test]
    fn bytes_that_settle_would_not_have_written_are_refused() {
        use SettlementRowError::{BadLength, OutcomeDisagrees, UnknownOutcome};
        assert_eq!(
            SettlementRow::from_bytes(&[0x01, 2]),
            Err(BadLength { found: 2 })
        );
        assert_eq!(
            SettlementRow::from_bytes(&[0x01, 2, 3, 0]),
            Err(BadLength { found: 4 })
        );
        // A zero-filled cell is not a row.
        assert_eq!(
            SettlementRow::from_bytes(&[0, 0, 0]),
            Err(UnknownOutcome { tag: 0 })
        );
        assert_eq!(
            SettlementRow::from_bytes(&[0x04, 0, 3]),
            Err(UnknownOutcome { tag: 4 })
        );
        // Served on one pass; Missed on two; observed on two issued.
        assert_eq!(
            SettlementRow::from_bytes(&[0x01, 1, 3]),
            Err(OutcomeDisagrees)
        );
        assert_eq!(
            SettlementRow::from_bytes(&[0x02, 2, 3]),
            Err(OutcomeDisagrees)
        );
        assert_eq!(
            SettlementRow::from_bytes(&[0x02, 0, 2]),
            Err(OutcomeDisagrees)
        );
    }

    #[test]
    fn the_digest_is_a_sum_that_wraps() {
        let mut one = [0u8; ISSUED_DIGEST_LEN];
        one[0] = 1;
        let mut top = [0xffu8; ISSUED_DIGEST_LEN];

        let mut digest = IssuedDigest::from_bytes(top);
        digest.fold(&one);
        assert_eq!(digest, IssuedDigest::ZERO);

        // Carries run the whole width, and order does not matter.
        top[0] = 0xfe;
        let mut a = IssuedDigest::ZERO;
        a.fold(&top);
        a.fold(&one);
        let mut b = IssuedDigest::ZERO;
        b.fold(&one);
        b.fold(&top);
        assert_eq!(a, b);
        assert_eq!(a.as_bytes(), &[0xff; ISSUED_DIGEST_LEN]);
    }
}
