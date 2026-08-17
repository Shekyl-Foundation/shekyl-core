// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot well-formedness for daemon fee estimates.
//!
//! The 2021-scaling daemon (`shekyld`, `HF_VERSION_2021_SCALING = 1` from
//! genesis) returns `Fl / Fn / Fm / Fh` with `Fh / Fl` routinely 65×–1000×
//! (`tests/unit_tests/scaling_2021.cpp`). An intra-snapshot "priority ≤ 10×
//! economy" lock is not a sanity ceiling against that daemon — it is a ban
//! on the honest Priority tier. That check is **withdrawn**. The historical
//! median-multiple ceiling remains the V3.x `WalletSideEstimator`'s job
//! (`FOLLOWUPS.md` §"wallet-side fee estimation").
//!
//! What *is* snapshot-shaped, and is enforced here once:
//!
//! 1. **Tier band monotonic** — `economy ≤ standard ≤ priority`. An
//!    inversion is a defect or a lie, not a market condition.
//! 2. **Absolute cap on the EFFECTIVE weight-1 charge** — for each
//!    named tier, `fee_from_weight(rate, 1) ≤ 100,000` atomic units.
//!    The effective charge, not the raw `per_weight`: every fee is
//!    rounded UP to a multiple of the daemon-controlled
//!    `quantization_mask`, so a raw-rate cap is bypassable by mask
//!    alone (tiers `(1,1,1)` with mask `10^18` would quantize every
//!    ordinary transaction to `10^18` units). The weight-1 charge is
//!    `≥ mask` and `≥ per_weight`, so one bound caps both without a
//!    second policy constant; the marginal per-weight cost stays
//!    `≤ per_weight ≤` the same bound, and mask rounding adds at most
//!    one mask unit (`≤` the cap) to any fee, once. Honest
//!    2021-scaling `Fh` in the KAT is 67,000 with a small mask.
//!
//! [`ValidatedFeeEstimates`] is the only constructor. Quote and build
//! both go through it; Custom band-checks run later, against a snapshot
//! that has already been accepted.
//!
//! `Custom` is bounded by the *same* two facts and nothing else — at or
//! above the snapshot's economy floor, at or below the cap on the same
//! effective basis. It gets no relative ceiling of its own: economy is
//! the market floor, so an economy multiple cannot separate a user's
//! typo from an honest top tier, and one anchored on `priority` would
//! be a free parameter. See [`CustomFeeBand`].

use core::num::NonZeroU64;

use shekyl_rpc_client::{tx_fee, FeeRate};

use super::traits::FeeEstimates;

/// Absolute per-weight cap (atomic units) on every named tier and on
/// `Custom`. History-free half of the 2026-04-25 decision-log entry;
/// pinned against the 2021-scaling KAT (`Fh = 67_000` at the 10 SKL /
/// 300 k-weight row).
///
/// `pub` because [`CeilingViolation::bound`] returns it as the
/// `-29109` wire payload's `bound` field: an RPC consumer reading
/// those docs must be able to follow the link to the number.
pub const ABSOLUTE_FEE_RATE_CAP: u64 = 100_000;

/// Failures from fee estimation / snapshot validation.
///
/// Distinct from a transport failure ([`Self::DaemonUnreachable`]) and
/// from a broken wire contract ([`Self::DaemonResponseInvalid`]):
/// [`Self::DaemonFeeUnreasonable`] is "the daemon answered and we refuse
/// to pay what it asked." `#[non_exhaustive]` so V3.x estimators can
/// extend the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FeeEstimatorError {
    /// The daemon RPC the estimator depends on was unreachable.
    #[error("fee estimator: daemon unreachable")]
    DaemonUnreachable,

    /// The daemon returned a response the estimator could not consume.
    #[error("fee estimator: daemon response invalid ({reason})")]
    DaemonResponseInvalid {
        /// Compile-time-fixed description of the contract violation.
        reason: &'static str,
    },

    /// Well-formed snapshot, refused by the sanity ceiling.
    #[error("fee estimator: daemon fee unreasonable ({0})")]
    DaemonFeeUnreasonable(CeilingViolation),

    /// The caller's `Custom` rate is outside the accepted band — a
    /// request error, not a daemon defect (RPC `-32602`).
    #[error("custom fee rate out of range ({0})")]
    CustomFeeOutOfRange(CustomFeeBand),
}

/// Snapshot-shaped ceiling violation. Wire `data` is `{reason, rate, bound}`
/// via [`Self::reason`] / [`Self::rate`] / [`Self::bound`]; monotonicity
/// carries all three tiers so the pair is never a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CeilingViolation {
    /// `economy ≤ standard ≤ priority` failed.
    #[error(
        "tier band not monotonic (economy={economy}, standard={standard}, priority={priority})"
    )]
    NonMonotonic {
        /// Per-weight economy rate.
        economy: u64,
        /// Per-weight standard rate.
        standard: u64,
        /// Per-weight priority rate.
        priority: u64,
    },
    /// A named tier's **effective weight-1 quantized charge** exceeds
    /// [`ABSOLUTE_FEE_RATE_CAP`] (the charge includes the
    /// daemon-controlled mask rounding — see the module docs for why
    /// the raw rate is not the checked quantity).
    #[error("tier above the absolute per-weight cap ({rate} > {cap})", cap = ABSOLUTE_FEE_RATE_CAP)]
    AboveAbsoluteCap {
        /// Offending effective weight-1 charge (atomic units).
        rate: u64,
    },
}

impl CeilingViolation {
    /// Stable `error.data.reason` token (compile-time-fixed).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NonMonotonic { .. } => "tier band not monotonic",
            Self::AboveAbsoluteCap { .. } => "tier above the absolute per-weight cap",
        }
    }

    /// Offending per-weight rate for the wire pair.
    ///
    /// For [`Self::NonMonotonic`], the first inverted left-hand value
    /// (`economy` if `economy > standard`, else `standard`).
    #[must_use]
    pub const fn rate(self) -> u64 {
        match self {
            Self::NonMonotonic {
                economy, standard, ..
            } => {
                if economy > standard {
                    economy
                } else {
                    standard
                }
            }
            Self::AboveAbsoluteCap { rate } => rate,
        }
    }

    /// Bound the offending rate violated.
    ///
    /// For [`Self::NonMonotonic`], the value the left-hand side should
    /// have been `≤` (`standard` if `economy > standard`, else `priority`).
    #[must_use]
    pub const fn bound(self) -> u64 {
        match self {
            Self::NonMonotonic {
                standard,
                priority,
                economy,
            } => {
                if economy > standard {
                    standard
                } else {
                    priority
                }
            }
            Self::AboveAbsoluteCap { .. } => ABSOLUTE_FEE_RATE_CAP,
        }
    }
}

/// Why a caller-pinned `Custom` rate was refused.
///
/// The band is exactly the policy every *named* tier obeys — no more,
/// no less. There is no `Custom`-only relative ceiling: an
/// economy-anchored multiple is the same category error the withdrawn
/// 10× lock was (economy is the market *floor*, and honest
/// 2021-scaling `Fh / Fl` reaches 1077×), so a "100× economy" ceiling
/// refused `Custom` at the snapshot's own Priority rate while
/// `FeePriority::Priority` succeeded at that identical rate. The
/// 2026-08-16 ruling names one bound for `Custom` — the absolute cap —
/// and that is what is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CustomFeeBand {
    /// Below the snapshot's economy floor — the daemon's own cheapest
    /// tier. Not paternalism: below it the transaction does not clear.
    #[error("custom feerate below economy floor")]
    BelowEconomyFloor,
    /// Effective weight-1 charge above [`ABSOLUTE_FEE_RATE_CAP`], on
    /// the same basis [`ValidatedFeeEstimates`] applies to every named
    /// tier. A rate that overflows the fee arithmetic is this variant
    /// too — it is certainly above the cap.
    #[error("custom feerate above the absolute per-weight cap")]
    AboveAbsoluteCap,
}

/// A daemon fee snapshot that passed `try_new`.
///
/// Field access goes through accessors so a raw (unvalidated) snapshot
/// cannot be mistaken for this type, and the constructor is
/// crate-internal: outside the engine this is an opaque token minted
/// only at the fetch boundary, so no consumer can hand the build path
/// a snapshot that skipped the ceiling. `Copy` so it rides
/// [`super::FeeEstimationContext`] the way the raw snapshot did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedFeeEstimates {
    inner: FeeEstimates,
    /// The non-zero proof for `inner.quantization_mask`, established
    /// once in [`Self::try_new`]. Carried rather than re-derived so no
    /// accessor needs an `expect` (or an unreachable error arm) to hand
    /// the mask to an infallible [`FeeRate::from_nonzero`].
    mask: NonZeroU64,
}

impl ValidatedFeeEstimates {
    /// Accept a snapshot or refuse it with a typed ceiling violation.
    ///
    /// # Errors
    ///
    /// [`FeeEstimatorError::DaemonResponseInvalid`] if a named rate's
    /// mask disagrees with the snapshot mask (or the mask is zero).
    /// [`FeeEstimatorError::DaemonFeeUnreasonable`] if the tier band is
    /// non-monotonic or any named tier exceeds the absolute cap.
    pub(crate) fn try_new(snapshot: FeeEstimates) -> Result<Self, FeeEstimatorError> {
        let mask = NonZeroU64::new(snapshot.quantization_mask).ok_or(
            FeeEstimatorError::DaemonResponseInvalid {
                reason: "quantization_mask is zero",
            },
        )?;
        for (rate, which) in [
            (&snapshot.economy, "economy"),
            (&snapshot.standard, "standard"),
            (&snapshot.priority, "priority"),
        ] {
            if rate.mask() != snapshot.quantization_mask {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: match which {
                        "economy" => "economy feerate mask disagrees with snapshot mask",
                        "standard" => "standard feerate mask disagrees with snapshot mask",
                        _ => "priority feerate mask disagrees with snapshot mask",
                    },
                });
            }
        }

        let economy = snapshot.economy.per_weight();
        let standard = snapshot.standard.per_weight();
        let priority = snapshot.priority.per_weight();

        // Raw rates for monotonicity: the tiers share one mask, so the
        // effective ordering follows the raw ordering exactly.
        if economy > standard || standard > priority {
            return Err(FeeEstimatorError::DaemonFeeUnreasonable(
                CeilingViolation::NonMonotonic {
                    economy,
                    standard,
                    priority,
                },
            ));
        }
        // EFFECTIVE weight-1 charge for the cap: the mask rounds every
        // fee up to a mask multiple, so the raw rate alone is
        // mask-bypassable (module docs). `fee(1) ≥ mask` also bounds
        // the mask itself under the same constant.
        for rate in [&snapshot.economy, &snapshot.standard, &snapshot.priority] {
            let one = tx_fee::try_fee_from_weight(rate, 1).ok_or(
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "feerate overflowed fee arithmetic at weight 1",
                },
            )?;
            if one > ABSOLUTE_FEE_RATE_CAP {
                return Err(FeeEstimatorError::DaemonFeeUnreasonable(
                    CeilingViolation::AboveAbsoluteCap { rate: one },
                ));
            }
        }
        Ok(Self {
            inner: snapshot,
            mask,
        })
    }

    /// Economy tier.
    #[must_use]
    pub fn economy(self) -> FeeRate {
        self.inner.economy
    }

    /// Standard tier.
    #[must_use]
    pub fn standard(self) -> FeeRate {
        self.inner.standard
    }

    /// Priority tier.
    #[must_use]
    pub fn priority(self) -> FeeRate {
        self.inner.priority
    }

    /// Snapshot quantization mask (shared by every named tier and by
    /// `Custom` construction).
    ///
    /// [`NonZeroU64`] because the constructor refused a zero mask —
    /// the proof travels with the value, so `Custom` construction is
    /// total.
    #[must_use]
    pub fn quantization_mask(self) -> NonZeroU64 {
        self.mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_client::FeeRate;

    fn snapshot(e: u64, s: u64, p: u64) -> FeeEstimates {
        FeeEstimates {
            economy: FeeRate::new(e, 1).expect("economy"),
            standard: FeeRate::new(s, 1).expect("standard"),
            priority: FeeRate::new(p, 1).expect("priority"),
            quantization_mask: 1,
        }
    }

    /// This bites against a fixture that inverts the band; it does NOT
    /// cover the withdrawn 10×-economy lock (that lock is gone).
    #[test]
    fn monotonicity_carries_all_three_tiers() {
        match ValidatedFeeEstimates::try_new(snapshot(20, 10, 50)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(v)) => {
                assert_eq!(
                    v,
                    CeilingViolation::NonMonotonic {
                        economy: 20,
                        standard: 10,
                        priority: 50,
                    }
                );
                assert_eq!(v.reason(), "tier band not monotonic");
                assert_eq!((v.rate(), v.bound()), (20, 10));
            }
            other => panic!("unexpected: {other:?}"),
        }
        match ValidatedFeeEstimates::try_new(snapshot(10, 50, 20)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(
                v @ CeilingViolation::NonMonotonic { .. },
            )) => {
                assert_eq!((v.rate(), v.bound()), (50, 20));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// This bites against a 2021-scaling-shaped snapshot being refused;
    /// it does NOT cover a historical median-multiple ceiling.
    #[test]
    fn twenty_twenty_one_scaling_kat_rows_are_well_formed() {
        // tests/unit_tests/scaling_2021.cpp `wallet_fee_estimate`,
        // mapped economy=fees[0], standard=fees[1], priority=fees[3].
        ValidatedFeeEstimates::try_new(snapshot(340, 1400, 67_000))
            .expect("10 SKL / 300k-zone Fh=67000 is 197× economy and must pass");
        ValidatedFeeEstimates::try_new(snapshot(340, 1400, 22_000))
            .expect("10 SKL / large-Mnw Fh=22000 is 65× economy and must pass");
        ValidatedFeeEstimates::try_new(snapshot(13, 53, 14_000))
            .expect("10 SKL / 1.5M-zone Fh=14000 is 1077× economy and must pass");
        ValidatedFeeEstimates::try_new(snapshot(10, 20, 101))
            .expect("the withdrawn 10× lock must not refuse 10.1×");
    }

    /// The finding's vector, pinned: a benign raw rate under an
    /// enormous daemon-controlled mask must NOT pass — the mask alone
    /// quantizes every ordinary transaction to one mask unit, which is
    /// the overpayment the cap exists to refuse. The negative controls
    /// keep honest small masks (the daemon's real rounding granularity)
    /// passing at the same raw rates.
    #[test]
    fn absolute_cap_is_on_the_effective_charge_not_the_raw_rate() {
        let masked = |e: u64, s: u64, p: u64, m: u64| FeeEstimates {
            economy: FeeRate::new(e, m).expect("economy"),
            standard: FeeRate::new(s, m).expect("standard"),
            priority: FeeRate::new(p, m).expect("priority"),
            quantization_mask: m,
        };

        // Raw rates of 1 pass a raw-rate cap; the 10^18 mask makes the
        // effective weight-1 charge 10^18. Refused, with the effective
        // charge in the wire pair.
        match ValidatedFeeEstimates::try_new(masked(1, 1, 1, 1_000_000_000_000_000_000)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => {
                assert_eq!(rate, 1_000_000_000_000_000_000);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Honest mask (the 2021-scaling daemon's rounding granularity):
        // same KAT raw rates pass — the fix must not refuse honesty.
        ValidatedFeeEstimates::try_new(masked(340, 1400, 67_000, 10_000))
            .expect("KAT row with an honest 10k mask passes");

        // Boundary: mask exactly at the cap with a tiny rate — the
        // effective charge is exactly the cap, and passes.
        ValidatedFeeEstimates::try_new(masked(1, 1, 1, 100_000))
            .expect("effective charge exactly at the cap passes");
        // One mask unit above: refused.
        match ValidatedFeeEstimates::try_new(masked(1, 1, 1, 100_001)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => assert_eq!(rate, 100_001),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn absolute_cap_refuses_only_over_the_bound() {
        match ValidatedFeeEstimates::try_new(snapshot(100_001, 100_001, 100_001)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => {
                assert_eq!(rate, 100_001);
            }
            other => panic!("unexpected: {other:?}"),
        }
        ValidatedFeeEstimates::try_new(snapshot(100_000, 100_000, 100_000))
            .expect("exactly the absolute cap is within the ceiling");
    }
}
