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
//!    named tier, `fee_from_weight(rate, 1) ≤`
//!    [`absolute_fee_rate_cap()`] (the daemon-rounded genesis-condition
//!    `Fh` = 14,000,000 atomic units — derived, KAT-pinned; a 100,000
//!    mid-regime literal was caught in review refusing honest
//!    young-chain snapshots whose economy tier alone is ~68,266).
//!    The effective charge, not the raw `per_weight`: every fee is
//!    rounded UP to a multiple of the daemon-controlled
//!    `quantization_mask`, so a raw-rate cap is bypassable by mask
//!    alone (tiers `(1,1,1)` with mask `10^18` would quantize every
//!    ordinary transaction to `10^18` units). The weight-1 charge is
//!    `≥ mask` and `≥ per_weight`, so one bound caps both without a
//!    second policy constant; the marginal per-weight cost stays
//!    `≤ per_weight ≤` the same bound, and mask rounding adds at most
//!    one mask unit (`≤` the cap) to any fee, once.
//!
//! [`ValidatedFeeEstimates`] is the only constructor. Quote and build
//! both go through it; Custom band-checks run later, against a snapshot
//! that has already been accepted.
//!
//! `Custom` is bounded by those two facts and nothing else — at or
//! above the snapshot's economy floor, at or below the same absolute
//! cap. It gets no relative ceiling of its own: economy is the market
//! floor, so an economy multiple cannot separate a user's typo from an
//! honest top tier, and one anchored on `priority` would be a free
//! parameter. The floor reads the raw per-weight rate and the ceiling
//! the effective weight-1 charge — different quantities on purpose,
//! because "does this undercut economy" and "how much can this cost"
//! are maximized at opposite ends of the weight range. See
//! [`CustomFeeBand`].

use core::num::NonZeroU64;

use shekyl_rpc_client::{tx_fee, FeeRate};

use super::traits::FeeEstimates;

/// `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` (`src/cryptonote_config.h`)
/// — the 2021-scaling reference transaction weight the daemon's fee
/// formula folds in.
const DYNAMIC_FEE_REFERENCE_TX_WEIGHT: u64 = 3_000;

/// The penalty-free zone / minimum median (`Zm`), single-sourced from
/// the wire crate's `MIN_BLOCK_WEIGHT`
/// (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`).
const PENALTY_FREE_ZONE: u64 = shekyl_wire::transaction::MIN_BLOCK_WEIGHT as u64;

/// `round_money_up(x, 2)` (`cryptonote_format_utils.cpp`): round UP to
/// two significant decimal digits — the daemon applies this to every
/// tier it returns, so the legitimate maximum must be computed
/// post-rounding. (The C++ comment says "5 or more"; the code bumps on
/// ANY nonzero remainder, and the code is the contract.)
const fn round_money_up_2(x: u64) -> u64 {
    if x < 100 {
        return x;
    }
    // unit = 10^(digit_count - 2)
    let mut unit: u64 = 1;
    let mut probe = x;
    while probe >= 100 {
        probe /= 10;
        unit *= 10;
    }
    x.div_ceil(unit).saturating_mul(unit)
}

/// Absolute cap (atomic units) on every named tier's — and `Custom`'s —
/// **effective weight-1 charge**: the maximum fee an honest daemon can
/// legitimately quote over the whole emission era.
///
/// Derived, not hand-picked. This review round caught a `100_000`
/// literal provisioned from a mid-regime KAT row — **140× below the
/// genesis-era `Fh`**, which would have refused every honest snapshot
/// from block 1 (young-chain `economy` alone is ~68,266; `standard`
/// is 4× that). The 2021-scaling fees rise with the block reward and
/// fall with the weight medians; the reward is maximal at genesis
/// (`base_block_reward(0)` — the estimate path uses the 5-arg reward,
/// no release multiplier) and both medians floor at the penalty-free
/// zone, so the era maximum is `Fh` at genesis conditions,
/// daemon-rounded:
///
/// ```text
/// Fm  = 16·R₀·Brw / Zm²                      (Mfw = Zm)
/// Fh  = max(4·Fm, 4·Fm·Zm / (32·Brw·Zm/Zm))  (Mnw = Zm) = 12.5·Fm
/// cap = round_money_up(Fh, 2) = 14,000,000
/// ```
///
/// Pinned by `absolute_cap_is_the_rounded_genesis_fh`, so an
/// economics-parameter change moves this loudly. Deliberately NOT
/// covering `BLOCK_REWARD_OVERESTIMATE` (the daemon's 10,000-SKL
/// placeholder when its own reward computation fails): a daemon that
/// just logged an internal error is not a daemon whose quote we pay —
/// refusing that snapshot is the cap working.
///
/// `pub` because [`CeilingViolation::bound`] returns it as the
/// `-29109` wire payload's `bound` field: an RPC consumer reading
/// those docs must be able to follow the link to the derivation.
#[must_use]
pub fn absolute_fee_rate_cap() -> u64 {
    let params = shekyl_economics::params::EconomicParams::default();
    let r0 = shekyl_economics::emission::base_block_reward(0, &params)
        .expect("genesis reward is defined for already_generated = 0");
    let zm = PENALTY_FREE_ZONE;
    let brw = DYNAMIC_FEE_REFERENCE_TX_WEIGHT;
    // The C++ folded integer expressions, verbatim, at Mfw = Mnw = Zm.
    let fm = 16 * r0 * brw / (zm * zm);
    let fh = std::cmp::max(4 * fm, 4 * fm * zm / (32 * brw * zm / zm));
    round_money_up_2(fh)
}

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
    /// [`absolute_fee_rate_cap()`] (the charge includes the
    /// daemon-controlled mask rounding — see the module docs for why
    /// the raw rate is not the checked quantity).
    #[error("tier above the absolute per-weight cap (effective weight-1 charge {rate})")]
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
    pub fn bound(self) -> u64 {
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
            Self::AboveAbsoluteCap { .. } => absolute_fee_rate_cap(),
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
    /// Effective weight-1 charge above [`absolute_fee_rate_cap()`], on
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
            // Fail-closed arithmetic: an overflowing weight-1 charge is
            // represented as `u64::MAX`, which the cap branch refuses as
            // what it is — a charge above any finite cap (`-29109`) —
            // rather than a malformed response (`-29102`). Same
            // disposition as `Custom`'s cap arm.
            let one = tx_fee::fee_from_weight(rate, 1);
            if one > absolute_fee_rate_cap() {
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
        let cap = absolute_fee_rate_cap();
        ValidatedFeeEstimates::try_new(masked(1, 1, 1, cap))
            .expect("effective charge exactly at the cap passes");
        // One unit above: refused.
        match ValidatedFeeEstimates::try_new(masked(1, 1, 1, cap + 1)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => assert_eq!(rate, cap + 1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// The overflow arm is an over-cap refusal, not a malformed
    /// response: a representable wire value whose weight-1 charge
    /// overflows the fee arithmetic is unambiguously above any finite
    /// cap and must answer `-29109` (`AboveAbsoluteCap`, saturated
    /// rate), never `-29102`.
    #[test]
    fn weight_one_overflow_is_over_cap_not_malformed() {
        let m = 2u64;
        let big = FeeEstimates {
            economy: FeeRate::new(u64::MAX, m).expect("economy"),
            standard: FeeRate::new(u64::MAX, m).expect("standard"),
            priority: FeeRate::new(u64::MAX, m).expect("priority"),
            quantization_mask: m,
        };
        match ValidatedFeeEstimates::try_new(big) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => assert_eq!(rate, u64::MAX, "saturated charge rides the wire pair"),
            other => panic!("overflow must be an over-cap refusal: {other:?}"),
        }
    }

    #[test]
    fn absolute_cap_refuses_only_over_the_bound() {
        let cap = absolute_fee_rate_cap();
        match ValidatedFeeEstimates::try_new(snapshot(cap + 1, cap + 1, cap + 1)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => {
                assert_eq!(rate, cap + 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
        ValidatedFeeEstimates::try_new(snapshot(cap, cap, cap))
            .expect("exactly the absolute cap is within the ceiling");
    }

    /// The cap IS the daemon-rounded genesis-condition `Fh` — pinned as
    /// a literal so an economics-parameter change moves it loudly, and
    /// cross-checked against the folded formula so a cap edit that
    /// bypasses the derivation fails here.
    #[test]
    fn absolute_cap_is_the_rounded_genesis_fh() {
        let cap = absolute_fee_rate_cap();
        assert_eq!(cap, 14_000_000, "economics params moved the era-max fee");

        let params = shekyl_economics::params::EconomicParams::default();
        let r0 = shekyl_economics::emission::base_block_reward(0, &params).expect("r0");
        assert_eq!(r0, 2_048_000_000_000, "genesis base reward moved");
        let fm = 16 * r0 * 3_000 / (300_000u64 * 300_000);
        let fh = 4 * fm * 300_000 / (32 * 3_000);
        assert_eq!(
            cap,
            round_money_up_2(fh),
            "cap must equal rounded genesis Fh"
        );
    }

    /// The finding's scenario, pinned end to end: the honest YOUNG-CHAIN
    /// snapshot — raw genesis-condition tiers and their daemon-rounded
    /// forms (what the wallet actually receives) — must be well-formed.
    /// This is the bootstrap-operation guarantee: build, quote, and
    /// first-stake all ride this constructor from block 1.
    #[test]
    fn genesis_condition_snapshots_are_well_formed() {
        // Raw folded-formula tiers at genesis conditions.
        ValidatedFeeEstimates::try_new(snapshot(68_266, 273_066, 13_653_325))
            .expect("raw genesis-condition tiers are honest and must pass");
        // Daemon-rounded (round_money_up, 2 significant digits): the
        // wire form. Priority lands exactly on the cap.
        ValidatedFeeEstimates::try_new(snapshot(69_000, 280_000, 14_000_000))
            .expect("rounded genesis-condition tiers are honest and must pass");
    }
}
