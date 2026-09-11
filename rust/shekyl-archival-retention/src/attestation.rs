// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation settlement fold — the per-`(P, shard, epoch)` decision that
//! turns an epoch's challenge outcomes into the three-valued serve-credit
//! settlement.
//!
//! Design of record: `ARCHIVAL_CHALLENGE_MECHANISM.md` §3 (nested
//! measurement) and §7.1 (threshold ratification, 2026-08-11). The round
//! landed on `dev` 2026-08-11, so that file is now the record directly —
//! the WIP branch and its superseded-in-place banner are retired. This
//! module owns
//! **only the settlement-time fold**; admission verifies countersignatures
//! elsewhere, and by settlement time the signatures are pruned by
//! construction — the fold reads only counts derived from kept data.
//!
//! ## The ratified rule: absolute-2
//!
//! [`settle_epoch`] takes `(passes, issued)` and settles **Served iff
//! `passes ≥ 2`, full stop** — the threshold is never a function of the
//! issued count. Majority-of-issued was rejected because it makes the
//! threshold depend on a derived quantity, coupling agreement on the bit to
//! every node reproducing the urn derivation identically; absolute-2 needs
//! only a pass count, the smaller consensus surface.
//!
//! `issued` still matters at the **observation floor**: a pair issued fewer
//! than 2 challenges can never reach the threshold, so its epoch settles
//! [`EpochSettlement::NonObservation`] — a pair the urn could not reach
//! twice is not a pair that failed. That keys the settlement-outcome row on
//! *issued*, not on drawable, and it is what the pruned/absent row decays
//! to (never `Missed`).
//!
//! **Reachability, stated so this branch is not misread:** the live schedule
//! is `CHALLENGES_PER_PAIR_PER_EPOCH = 3`, and under the exact-min urn at
//! exact budget every drawable pair receives exactly that — so the
//! under-issuance arm is *unreachable* in normal operation. It goes live
//! only in the capped regime (`k_cap` binding; the §8 72 %-unobservable
//! case), i.e. only if the tx-carrier prunable-residence work does not land.
//! It is specified defensively, not as tolerance for short issuance by
//! design.
//!
//! The former `to_observation`/`is_observation` bridge to the m-of-n
//! machinery is **deleted** (ruled with the 2-of-3 adoption): consumers at
//! the settlement/window seam construct their two-valued observation from
//! the settlement directly, and the integration test does exactly that.

/// The kept per-record discriminant. `Pass` carried a countersignature (now
/// pruned); under the ruled mechanism a miss is never asserted on the wire
/// (expiry ⇒ miss), so `Miss` survives here only for the **interim** kept
/// headers the admission surface still parses — it retires with the format
/// round's deletion surface, not with this fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKind {
    /// A countersigned pass: `P` served the read and signed the
    /// block-bound nonce.
    Pass,
    /// Interim kept-header miss record (see type-level note above).
    Miss,
}

/// Served requires this many passes — the 2-of-3 ruling's absolute
/// threshold. Deliberately **not** a function of the issued count; re-pin
/// only together with `(m, n)` (the outer window prices what one epoch
/// observation means).
///
/// Jointly pinned with [`crate::constants::CHALLENGES_PER_PAIR_PER_EPOCH`]
/// (λ = 3): 2-of-3 is **one** decision, and the two const-asserts below are
/// what make it one rather than two numbers that can drift apart.
pub const SERVE_THRESHOLD_PASSES: u32 = 2;

// The 2-of-3 pin, as two properties §3 actually ruled — a re-pin of either
// constant that breaks one of these fails the build, so the pair cannot
// silently become something the §3 derivation never priced.
const _: () = assert!(
    SERVE_THRESHOLD_PASSES <= crate::constants::CHALLENGES_PER_PAIR_PER_EPOCH,
    "a threshold above the issued count makes Served unreachable: every epoch \
     would settle NonObservation and no pair could ever earn serve credit"
);
const _: () = assert!(
    2 * SERVE_THRESHOLD_PASSES > crate::constants::CHALLENGES_PER_PAIR_PER_EPOCH,
    "the threshold must be a STRICT MAJORITY of the challenges issued: a \
     minority threshold is the biased estimator §3 rejected pass-priority for \
     (1-of-3 more than doubles a liar's per-epoch pass rate over 1-of-1)"
);

/// The three-valued settlement of one `(P, shard, epoch)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSettlement {
    /// `passes ≥ 2`: `serve_credit_bit = 1`, an observation.
    Served,
    /// Observed (issued ≥ 2) but under threshold: `serve_credit_bit = 0`,
    /// counts as a miss in the outer window — under 2-of-3 this is the
    /// *stronger* claim "failed a majority", which is why `(m, n)` re-pins
    /// against the 2-of-3 tails rather than carrying forward.
    Missed,
    /// Issued < 2 — the pair could never have reached the threshold, so
    /// the window never sees the epoch. This is the value a pruned or
    /// absent settlement row decays to; never `Missed`.
    NonObservation,
}

/// Why a `(passes, issued)` pair was refused rather than settled.
///
/// The two counts reach the fold from **independent sources** — `passes`
/// from admission-verified records, `issued` from the urn derivation — so
/// a desync between them is a reachable runtime state on the settlement
/// path, and it must reject (the block, upstream) rather than panic the
/// daemon. Same posture as the urn's own [`crate::FeedError`]: a stream
/// the fold cannot trust is a typed refusal, never a crash and never a
/// silently "clamped" settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SettleError {
    /// More passes counted than challenges assigned — the record count and
    /// the urn bookkeeping disagree about the same pair-epoch.
    #[error(
        "more passes ({passes}) than issued challenges ({issued}): passes come from \
         admission-verified records and issued from the urn derivation, so this pair \
         is a desynced accounting input, not a settlement state"
    )]
    MorePassesThanIssued {
        /// Admission-verified pass records counted for the pair-epoch.
        passes: u32,
        /// Challenges the urn derivation assigned to the pair-epoch.
        issued: u32,
    },
}

/// Fold one epoch's challenge outcome counts for one `(P, shard)` into the
/// three-valued settlement — **absolute-2** (§7.1 ratification).
///
/// `passes` is the number of admission-verified pass records for the pair
/// in this epoch; `issued` is the number of challenges the derivation
/// assigned to it (a derived quantity — `ChallengeUrn::draws_done`
/// bookkeeping — never counted from records, §4.2).
///
/// # Errors
///
/// [`SettleError::MorePassesThanIssued`] if `passes > issued` — see
/// [`SettleError`] for why that is a typed refusal rather than a panic.
pub fn settle_epoch(passes: u32, issued: u32) -> Result<EpochSettlement, SettleError> {
    if passes > issued {
        return Err(SettleError::MorePassesThanIssued { passes, issued });
    }
    if issued < SERVE_THRESHOLD_PASSES {
        return Ok(EpochSettlement::NonObservation);
    }
    Ok(if passes >= SERVE_THRESHOLD_PASSES {
        EpochSettlement::Served
    } else {
        EpochSettlement::Missed
    })
}

impl EpochSettlement {
    /// `serve_credit_bit(P, s, E)` — `1` iff served. Missed and
    /// non-observation both yield `0`; the observation distinction they
    /// carry lives in the three-valued settlement itself, which is why the
    /// pruned epoch decays to non-observation rather than to a `0` the
    /// window would read as a miss.
    #[must_use]
    pub fn serve_credit_bit(self) -> bool {
        matches!(self, EpochSettlement::Served)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_issued_epochs_are_non_observations_even_with_a_pass() {
        // The discriminant absolute-2 forces: 1 pass of 1 issued is NOT a
        // served epoch — the pair never had a path to the threshold, so
        // the epoch is outside the window entirely. This is the §4.2
        // "a pair the urn could not reach is not a pair that failed"
        // distinction, now keyed on issuance.
        for (passes, issued) in [(0, 0), (0, 1), (1, 1)] {
            let s = settle_epoch(passes, issued).unwrap();
            assert_eq!(s, EpochSettlement::NonObservation, "{passes}/{issued}");
            assert!(!s.serve_credit_bit());
        }
    }

    #[test]
    fn served_iff_at_least_two_passes_regardless_of_issued() {
        // Absolute-2: the threshold never moves with the denominator.
        for (passes, issued) in [(2, 2), (2, 3), (3, 3), (2, 4), (4, 4)] {
            assert_eq!(
                settle_epoch(passes, issued),
                Ok(EpochSettlement::Served),
                "{passes}/{issued}"
            );
            assert!(settle_epoch(passes, issued).unwrap().serve_credit_bit());
        }
    }

    #[test]
    fn observed_but_under_threshold_is_missed() {
        // One pass of three is MISSED — the strictly stronger signal the
        // 2-of-3 adoption bought (under retired pass-priority this epoch
        // settled Served). Zero passes of two-plus likewise.
        for (passes, issued) in [(0, 2), (1, 2), (0, 3), (1, 3), (1, 4)] {
            let s = settle_epoch(passes, issued).unwrap();
            assert_eq!(s, EpochSettlement::Missed, "{passes}/{issued}");
            assert!(!s.serve_credit_bit());
        }
    }

    #[test]
    fn missed_and_non_observation_share_a_zero_bit_but_are_distinct() {
        // Both yield serve_credit_bit = 0; only their settlement values
        // differ — collapsing them would let a pruned (non-observation)
        // epoch read as a miss and slash an archiver for an epoch the urn
        // never reached twice.
        let missed = settle_epoch(0, 3).unwrap();
        let non_obs = settle_epoch(1, 1).unwrap();
        assert_eq!(missed.serve_credit_bit(), non_obs.serve_credit_bit());
        assert_ne!(missed, non_obs);
    }

    #[test]
    fn more_passes_than_issued_is_a_typed_refusal() {
        // A record count exceeding the urn's issued count is a desynced
        // accounting input — refused with both numbers named, never folded
        // (and never a panic on the settlement path).
        assert_eq!(
            settle_epoch(3, 2),
            Err(SettleError::MorePassesThanIssued {
                passes: 3,
                issued: 2
            })
        );
    }
}
