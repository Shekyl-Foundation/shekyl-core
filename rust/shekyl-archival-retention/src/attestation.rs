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
/// # What this guards (`SO-D8d`, 2026-09-16)
///
/// Under `SO-D8b` (exact-get dedup + membership;
/// `docs/design/ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §6), `passes > issued`
/// is unreachable by construction: one record per `(P, s, E, h)`, each `h`
/// tied to a draw, `E = epoch(h)`. This error is **not** an arithmetic
/// disagreement that can arise on its own. It is a cheap backstop under
/// two stronger local layers that guard **Q3** — whether the drawable-set
/// reconstruction is stable between admission at `h_incl` and settlement
/// at the slash deadline, hundreds of blocks later:
///
/// 1. per-record assignment equality against the writer's `assignment(h)`
///    (a streamed replay, not a materialised epoch);
/// 2. a local 32-byte digest of the drawable set, persisted in the connect
///    batch at `h_open(E)`, compared against a re-walk of the set at the
///    slash pass.
///
/// This variant is **strictly dominated**: it fires only when
/// `passes ≥ issued + 1`, which requires records, which layer 1 already
/// covers. Neither direction that costs a bond reaches it — an
/// over-derived `issued` (`NonObservation` read as `Missed`) or an
/// under-derived one (`Missed` read as `NonObservation`, the free exit)
/// both satisfy `passes ≤ issued`. Those are layer 2's alone (§6.1).
///
/// Four edits make the stack fire, each a different real defect: revert
/// the dedup widening (layers 1/3); perturb the reconstruction so
/// admission and settlement disagree (layer 2); prune a journal above the
/// retention horizon (fires upstream, as the enumerator's refusal or an
/// SI-7 view fault, and escalates at the slash pass); compile the
/// `cfg(test)` λ constructor into a production module (layer 1 only —
/// Q4 is a coverage precondition). Named here so a sweep does not read
/// an unreachable check as dead.
///
/// # What the caller must do
///
/// `settle_epoch` returns a typed refusal (same posture as the urn's
/// [`crate::FeedError`]). At the slash-pass caller it is a **store-invariant
/// Fault** — `poison().arm(<SI- row>)` → `ConnectState::Halted`, the row
/// minted at Slice C — never a `CenRow`, never `InvalidBlock`. The slash
/// pass runs inside the connect batch, so the block at the slash height is
/// not written on this node **because the writer halted, not because the
/// block is invalid**; other nodes connect it. The halt is in memory,
/// re-derived on restart, reads stay open. Never panic. Never clamp
/// (`min(passes, issued)`). Never skip (write no row — `SO-D5` inversion:
/// absent reads as NonObservation).
///
/// *SUPERSEDED: "a reachable runtime state on the settlement path" in
/// the arithmetic sense; "must reject (the block, upstream)".*
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SettleError {
    /// More admitted pass records than derived issuance for the pair-epoch —
    /// the cheap backstop under the `SO-D8d` layers. Not an arithmetic
    /// disagreement that can arise on its own once `SO-D8b` holds: either
    /// admission let in records the derivation never assigned (a dedup or
    /// membership regression — §6.5's first falsifier, with reconstruction
    /// agreeing), or the drawable-set derivation itself disagrees between
    /// admission and settlement (the Q3 case). The message names both so an
    /// operator is not sent to one subsystem when the fault is in the other.
    #[error(
        "more admitted pass records ({passes}) than derived issuance ({issued}) \
         for the pair-epoch: admission credited records the derivation did not \
         assign (dedup/membership regression) or the drawable-set derivation \
         disagrees between admission and settlement (SO-D8d); a store-invariant \
         fault, not a settlement state"
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
/// [`SettleError`] for why that is a typed refusal (the slash-pass
/// caller **halts**; never a panic, never a clamp, never a skip).
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
        // Layer-3 mapping pin (`SO-D8d`): the fold refuses rather than
        // clamping. This is not the Q3 reconstruction fixture — that seeds
        // two urns from divergent drawable sets at Slice C.
        assert_eq!(
            settle_epoch(3, 2),
            Err(SettleError::MorePassesThanIssued {
                passes: 3,
                issued: 2
            })
        );
    }
}
