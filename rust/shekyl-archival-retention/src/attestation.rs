// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation settlement fold — the §4 decision that turns an epoch's
//! **kept attestation headers** into the three-valued serve-credit settlement
//! for one `(P_id, shard)` pair.
//!
//! Design of record: [`ARCHIVAL_CREDIT_WIRE.md`](../../../docs/design/ARCHIVAL_CREDIT_WIRE.md)
//! (TJ-B step 3, shape 4). This module owns **only the settlement-time fold** —
//! the per-`(P, s, E)` rule that reads kept headers and produces the bit. It is
//! deliberately the *settlement* half of the admission↔settlement seam (§4):
//!
//! - **Admission** (block validation, pre-prune) verifies the countersignatures
//!   against the mined `attestation_root`. It lives elsewhere — this module
//!   never sees a signature.
//! - **Settlement** (slash-deadline scan, post-prune) folds the kept headers.
//!   By then the signatures are gone by construction, so this fold must read
//!   only what survives the prune: the per-record [`AttestationKind`].
//!
//! **The seam is a type, not a discipline.** [`settle_epoch`] takes `&[AttestationKind]`
//! — it is *structurally incapable* of reaching a signature, an `r`, or a nonce,
//! so a future maintainer cannot accidentally add a signature check at
//! settlement: there is nothing of the sort in the input. That is the
//! make-bad-states-unrepresentable form of "settlement must not touch pruned
//! data" (§4).

use crate::failure_window::BaselineObservation;

/// The kept per-record discriminant (§3.1): a pass carried a countersignature
/// (now in the pruned side table); a miss carried none. **Only the kind
/// survives the prune**, in the coinbase `tx_extra` header, committed via
/// `prefix_hash` — which is exactly, and only, what the settlement fold needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKind {
    /// A countersigned pass: `P` served the read and signed the block-bound
    /// nonce. The signature is admission-verified and then prunable.
    Pass,
    /// A miss: the producer challenged `(P, s, E)` and recorded no valid
    /// response. Carries no signature at any point.
    Miss,
}

/// The three-valued settlement of one `(P, shard, epoch)` (§4). Wider than the
/// two-valued [`BaselineObservation`] because the failure window must
/// distinguish a *missed observation* (counts toward m-of-n) from a
/// *non-observation* (the window never sees the epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSettlement {
    /// At least one pass: `serve_credit_bit = 1`, an observation.
    Served,
    /// Observed (≥ 1 record) but no pass: `serve_credit_bit = 0`, an
    /// observation that counts as a miss in the window.
    Missed,
    /// No record for the pair this epoch: the window never sees it. This is the
    /// value a **pruned** epoch decays to (§4 / `failure_window.rs:178-184`
    /// hazard) — never `Missed`.
    NonObservation,
}

/// Fold an epoch's attestation records for one `(P, shard)` into the
/// three-valued settlement, **pass-priority**.
///
/// Pass-priority (any authenticated pass dominates any number of misses) is the
/// fabrication-containment property: a fabricated miss only survives in an
/// epoch no diligent read covered, so a single real pass clears the epoch.
///
/// `kinds` is the multiset of records the settlement scan gathered for this
/// pair at this epoch — order-independent (the fold is a reduction). Empty ⇒
/// non-observation.
#[must_use]
pub fn settle_epoch(kinds: &[AttestationKind]) -> EpochSettlement {
    if kinds.is_empty() {
        return EpochSettlement::NonObservation;
    }
    if kinds.iter().any(|k| matches!(k, AttestationKind::Pass)) {
        EpochSettlement::Served
    } else {
        EpochSettlement::Missed
    }
}

impl EpochSettlement {
    /// `serve_credit_bit(P, s, E)` — `1` iff served. Missed and non-observation
    /// both yield `0`; the *observation* distinction they carry is
    /// [`Self::is_observation`], not this bit (the bit alone cannot tell a miss
    /// from an unseen epoch — which is why the settlement is three-valued and
    /// the pruned epoch decays to non-observation rather than to a `0` the
    /// window would read as a miss).
    #[must_use]
    pub fn serve_credit_bit(self) -> bool {
        matches!(self, EpochSettlement::Served)
    }

    /// Whether the failure window sees this epoch at all. `Served`/`Missed` are
    /// observations; `NonObservation` is skipped by the walk.
    #[must_use]
    pub fn is_observation(self) -> bool {
        !matches!(self, EpochSettlement::NonObservation)
    }

    /// Project to the window's two-valued [`BaselineObservation`], or `None`
    /// for a non-observation the window must not count. This is the sole bridge
    /// from the three-valued settlement to the existing m-of-n machinery.
    #[must_use]
    pub fn to_observation(self, settlement_epoch: u64) -> Option<BaselineObservation> {
        match self {
            EpochSettlement::Served => Some(BaselineObservation::served(settlement_epoch)),
            EpochSettlement::Missed => Some(BaselineObservation::missed(settlement_epoch)),
            EpochSettlement::NonObservation => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AttestationKind::{Miss, Pass};

    #[test]
    fn empty_is_non_observation() {
        // No record for the pair this epoch: the window never sees it. This is
        // the value a pruned epoch decays to, and it must never read as a miss.
        let s = settle_epoch(&[]);
        assert_eq!(s, EpochSettlement::NonObservation);
        assert!(!s.is_observation());
        assert!(!s.serve_credit_bit());
        assert_eq!(s.to_observation(42), None);
    }

    #[test]
    fn any_pass_dominates_regardless_of_miss_count() {
        // Pass-priority, the fabrication-containment property: one real pass
        // clears the epoch no matter how many misses a fabricator filed.
        for misses in 0..8 {
            let mut kinds = vec![Pass];
            kinds.extend(std::iter::repeat_n(Miss, misses));
            // Order must not matter — the fold is a reduction.
            for perm in [kinds.clone(), {
                let mut r = kinds.clone();
                r.reverse();
                r
            }] {
                let s = settle_epoch(&perm);
                assert_eq!(s, EpochSettlement::Served, "misses={misses}");
                assert!(s.serve_credit_bit());
                assert_eq!(s.to_observation(7), Some(BaselineObservation::served(7)));
            }
        }
    }

    #[test]
    fn observed_but_no_pass_is_a_missed_observation() {
        // A miss is an OBSERVATION (counts to the m-of-n window) but not a
        // pass, so serve_credit_bit is 0 while is_observation stays true — the
        // distinction the bit alone cannot carry.
        for n in 1..6 {
            let kinds = vec![Miss; n];
            let s = settle_epoch(&kinds);
            assert_eq!(s, EpochSettlement::Missed);
            assert!(s.is_observation(), "a miss is still an observation");
            assert!(!s.serve_credit_bit());
            assert_eq!(s.to_observation(9), Some(BaselineObservation::missed(9)));
        }
    }

    #[test]
    fn missed_and_non_observation_share_a_zero_bit_but_differ_at_the_window() {
        // The load-bearing three-valued distinction: both yield serve_credit_bit
        // = 0, but only Missed is an observation. If these collapsed, a pruned
        // (non-observation) epoch would read as a miss and slash an archiver for
        // an epoch it was never challenged in.
        let missed = settle_epoch(&[Miss]);
        let non_obs = settle_epoch(&[]);
        assert_eq!(missed.serve_credit_bit(), non_obs.serve_credit_bit()); // both 0
        assert_ne!(missed.is_observation(), non_obs.is_observation()); // but differ
        assert!(missed.to_observation(1).is_some());
        assert!(non_obs.to_observation(1).is_none());
    }
}
