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
//! 2. **Absolute cap on the per-weight rate** — for each named tier,
//!    `per_weight ≤` [`absolute_fee_rate_cap()`]: the exact structural
//!    maximum of the served priority rung, every factor at its own
//!    extreme, derived from the parameters and KAT-pinned. The rate is the
//!    whole of what the daemon serves: the lattice a fee is rounded up to
//!    (`shekyl_economics::FEE_QUANTIZATION_MASK`) is a Rust constant the
//!    wallet and the daemon share, not a daemon input, so there is no
//!    daemon-controlled rounding for a cap to bound.
//!
//! [`ValidatedFeeEstimates`] is the only constructor. Quote and build
//! both go through it; Custom band-checks run later, against a snapshot
//! that has already been accepted.
//!
//! `Custom` is bounded by those two facts and nothing else — at or
//! above the snapshot's economy floor, at or below the same absolute
//! cap, both read on the per-weight rate. It gets no relative ceiling of
//! its own: economy is the market floor, so an economy multiple cannot
//! separate a user's typo from an honest top tier, and one anchored on
//! `priority` would be a free parameter. See [`CustomFeeBand`].

use shekyl_rpc_client::FeeRate;

use super::traits::FeeEstimates;

/// Absolute cap (atomic units per weight) on every named tier's — and
/// `Custom`'s — per-weight rate: the maximum fee rate an honest daemon can
/// quote over the whole emission era.
///
/// A **structural bound**, not a swept maximum: the served priority rung is
/// `2·R·C/M`, a product whose factors peak at different ages — `R` is
/// largest at genesis, while `C` grows as `σ` decays and the burn fraction
/// rises with the supply ratio — so its maximum over the chain's life is
/// not at any single state a sweep can be sure to visit. Taking every
/// factor at its own extreme, from the parameters, gives a bound no
/// reachable state exceeds:
///
/// ```text
/// C   = (1−σ)·M_r/(1−b)  ≤  ⌊SCALE·release_max/(SCALE−burn_cap)⌋  (σ ⇒ 0)
///       — the exact maximum: `fee_correction` is monotone in each of its
///         clamped operands, so this is its value at the extremes, 13.0
///         at canonical parameters, with no rounding on top.
/// R   ≤ base_block_reward(0)                                (monotone in already_generated)
/// Mfw ≥ Zm
/// cap = corrected_fee_ladder(R₀, Zm, w_ref, C_max).priority
/// ```
///
/// The bound is loose against the reachable maximum by design: a cap exists
/// to refuse an absurd quote, and refusing an honest one dead-letters the
/// wallet, so soundness beats tightness. Two tests carry the two halves of
/// the guarantee:
/// `absolute_cap_is_the_structural_bound` pins this value so a parameter
/// change moves it loudly, while
/// `absolute_cap_bounds_the_swept_reachable_maximum` is the one that
/// matters — it sweeps the reachable surface and fails if an honest quote
/// ever exceeds the bound. Deliberately NOT covering
/// `BLOCK_REWARD_OVERESTIMATE` (the daemon's 10,000-SKL placeholder when
/// its own reward computation fails): a daemon that just logged an
/// internal error is not a daemon whose quote we pay — refusing that
/// snapshot is the cap working.
///
/// `pub` because [`CeilingViolation::bound`] returns it as the
/// `-29109` wire payload's `bound` field: an RPC consumer reading
/// those docs must be able to follow the link to the derivation.
#[must_use]
pub fn absolute_fee_rate_cap() -> u64 {
    let params = shekyl_economics::params::EconomicParams::default();
    let r0 = shekyl_economics::emission::base_block_reward(0, &params)
        .expect("genesis reward is defined for already_generated = 0");
    shekyl_economics::corrected_fee_ladder(
        r0,
        params.full_reward_zone,
        shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        shekyl_economics::FeeCorrection::from_scaled(structural_max_correction(&params)),
        &params,
    )
    .priority
}

/// The largest SCALE-unit multiplier the served ladder can carry: raw `C`
/// at `σ = 0`, `M_r = release_max`, `b = burn_cap`. `fee_correction`'s
/// own expression at its operands' extremes, so this IS the maximum,
/// not a bound over it.
fn structural_max_correction(params: &shekyl_economics::params::EconomicParams) -> u64 {
    let scale = u128::from(shekyl_economics::params::SCALE);
    let c_max = scale * u128::from(params.release_max) / (scale - u128::from(params.burn_cap));
    u64::try_from(c_max).expect("C bound fits u64")
}

/// Failures from fee estimation / snapshot validation.
///
/// Distinct from a failed daemon query ([`Self::Daemon`]) and from a
/// snapshot that arrived and could not be used ([`Self::DaemonResponseInvalid`]):
/// [`Self::DaemonFeeUnreasonable`] is "the daemon answered and we refuse
/// to pay what it asked." `#[non_exhaustive]` so V3.x estimators can
/// extend the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FeeEstimatorError {
    /// The daemon query the estimator depends on failed. The fault says
    /// how: no answer, a daemon this wallet cannot use, or a reply that
    /// broke the contract.
    #[error("fee estimator: daemon query failed ({0})")]
    Daemon(shekyl_rpc_client::DaemonFault),

    /// The daemon's snapshot arrived and the estimator could not use it.
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
    /// A named tier's per-weight rate exceeds [`absolute_fee_rate_cap()`].
    #[error("tier above the absolute per-weight cap (rate {rate})")]
    AboveAbsoluteCap {
        /// Offending per-weight rate (atomic units per weight).
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
    /// Per-weight rate above [`absolute_fee_rate_cap()`], the same bound
    /// [`ValidatedFeeEstimates`] applies to every named tier.
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
}

impl ValidatedFeeEstimates {
    /// Accept a snapshot or refuse it with a typed ceiling violation.
    ///
    /// # Errors
    ///
    /// [`FeeEstimatorError::DaemonFeeUnreasonable`] if the tier band is
    /// non-monotonic or any named tier's rate exceeds the absolute cap.
    pub(crate) fn try_new(snapshot: FeeEstimates) -> Result<Self, FeeEstimatorError> {
        let economy = snapshot.economy.per_weight();
        let standard = snapshot.standard.per_weight();
        let priority = snapshot.priority.per_weight();

        if economy > standard || standard > priority {
            return Err(FeeEstimatorError::DaemonFeeUnreasonable(
                CeilingViolation::NonMonotonic {
                    economy,
                    standard,
                    priority,
                },
            ));
        }
        // The band is monotone, so the priority rate is the largest; one
        // comparison caps all three.
        if priority > absolute_fee_rate_cap() {
            return Err(FeeEstimatorError::DaemonFeeUnreasonable(
                CeilingViolation::AboveAbsoluteCap { rate: priority },
            ));
        }
        Ok(Self { inner: snapshot })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_client::FeeRate;

    fn snapshot(e: u64, s: u64, p: u64) -> FeeEstimates {
        FeeEstimates {
            economy: FeeRate::new(e).expect("economy"),
            standard: FeeRate::new(s).expect("standard"),
            priority: FeeRate::new(p).expect("priority"),
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
        // mapped economy=fees[0], standard=fees[1], priority=fees[2].
        //
        // These MIRROR that file's rows (the served ladder at `C` = 1, no
        // rounding step, `standard` = 4F exactly), so they move when it
        // moves — which is the only thing that makes a mirrored constant a
        // cross-check rather than a second copy free to drift.
        ValidatedFeeEstimates::try_new(snapshot(333, 1332, 66_666))
            .expect("10 SKL / 300k-zone Fh=66666 is 200× economy and must pass");
        ValidatedFeeEstimates::try_new(snapshot(13, 52, 13_333))
            .expect("10 SKL / 1.5M-zone Fh=13333 is 1025× economy and must pass");
        ValidatedFeeEstimates::try_new(snapshot(10, 20, 101))
            .expect("the withdrawn 10× lock must not refuse 10.1×");
    }

    /// A saturated rate is an over-cap refusal, not a malformed response:
    /// `u64::MAX` per weight is unambiguously above any finite cap and
    /// must answer `-29109` (`AboveAbsoluteCap`), never `-29102`.
    #[test]
    fn a_saturated_rate_is_over_cap_not_malformed() {
        match ValidatedFeeEstimates::try_new(snapshot(u64::MAX, u64::MAX, u64::MAX)) {
            Err(FeeEstimatorError::DaemonFeeUnreasonable(CeilingViolation::AboveAbsoluteCap {
                rate,
            })) => assert_eq!(rate, u64::MAX, "the saturated rate rides the wire pair"),
            other => panic!("a saturated rate must be an over-cap refusal: {other:?}"),
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
    /// The cap is the STRUCTURAL maximum (see `absolute_fee_rate_cap`),
    /// and this pins its value so a parameter change moves it loudly.
    #[test]
    fn absolute_cap_is_the_structural_bound() {
        let p = shekyl_economics::params::EconomicParams::default();
        assert_eq!(
            structural_max_correction(&p),
            13 * shekyl_economics::params::SCALE,
            "C_max = ⌊SCALE·release_max/(SCALE−burn_cap)⌋ is exactly 13.0 at canonical params"
        );
        // 88,746,666 = ⌊2·R₀·C_max/(Zm·SCALE)⌋ with R₀ = 1,024,000,000,000
        // (1,024 SKL), C_max = 13·SCALE and Zm = 300,000: the arithmetic's
        // own answer, no rounding on any factor.
        assert_eq!(
            absolute_fee_rate_cap(),
            88_746_666,
            "economics params moved the structural fee bound"
        );
    }

    /// The bound must actually bound. This walks emission trajectories
    /// and, at every registered chain age, evaluates the served priority
    /// rung across the reachable volume grid; the maximum it finds must sit
    /// at or under the cap.
    ///
    /// **It sweeps trajectories, not just states**, because history moves
    /// `R`: a slower-emitting past leaves more `remaining`, and so a larger
    /// `R` at the same height. The release rails are swept as the
    /// accumulation extremes, a chain dormant at the `M_r = 0.8` rail and
    /// then busy among them.
    ///
    /// **It does not enumerate reachable histories** — arbitrary volume
    /// paths are uncountable — which is why the cap is a structural bound
    /// rather than a swept maximum. What this test guarantees is a floor
    /// under the bound's adequacy, not a proof of tightness. If it fails,
    /// the cap is refusing honest daemon quotes — a wallet liveness failure
    /// — and the bound must be re-derived before the literal is touched.
    #[test]
    fn absolute_cap_bounds_the_swept_reachable_maximum() {
        use shekyl_economics::params::SCALE;
        let p = shekyl_economics::params::EconomicParams::default();
        let zm = p.full_reward_zone;
        let cap = absolute_fee_rate_cap();

        // The accumulation extremes: a chain that has emitted as slowly
        // as the release multiplier allows retains the most `remaining`,
        // and therefore prices highest at any given age.
        let mut worst = (0u64, 0u64, 0u64, 0u64);
        for &m_r in &[p.release_min, SCALE, p.release_max] {
            let mut ag: u64 = 0;
            let max_h = 30 * shekyl_economics::BLOCKS_PER_YEAR;
            for h in 0..=max_h {
                if h % shekyl_economics::BLOCKS_PER_YEAR == 0 {
                    let base = shekyl_economics::emission::base_block_reward(ag, &p)
                        .expect("base reward along the trajectory");
                    let sigma = shekyl_economics::emission_share_at(h);
                    for v in [0u64, 5, 50, 100, 200, 500] {
                        let b = shekyl_economics::calc_burn_pct(
                            shekyl_economics::TxVolume::per_block(v),
                            p.tx_volume_baseline,
                            ag,
                            p.emission_curve_asymptote,
                            p.burn_base_rate,
                            p.burn_cap,
                        );
                        let c = shekyl_economics::fee_correction(
                            shekyl_economics::TxVolume::per_block(v),
                            sigma,
                            b,
                            &p,
                        );
                        let prio = shekyl_economics::corrected_fee_ladder(
                            base,
                            zm,
                            shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT,
                            c,
                            &p,
                        )
                        .priority;
                        if prio > worst.0 {
                            worst = (prio, h / shekyl_economics::BLOCKS_PER_YEAR, v, m_r);
                        }
                    }
                }
                if h < max_h {
                    // Advance along THIS trajectory's release rail.
                    let paid = shekyl_economics::emission::base_block_reward(ag, &p)
                        .expect("base reward along the trajectory");
                    ag = ag.saturating_add(
                        u64::try_from(u128::from(paid) * u128::from(m_r) / u128::from(SCALE))
                            .unwrap_or(u64::MAX),
                    );
                }
            }
        }

        assert!(
            worst.0 <= cap,
            "an honest quote exceeds the cap: swept maximum {} (age {}y, v={}, rail M_r={}) > cap {}",
            worst.0,
            worst.1,
            worst.2,
            worst.3,
            cap
        );
        // Peak over the swept trajectories, not every reachable history.
        // The rail only sets how much has been emitted: a dormant past keeps
        // more `remaining`, so a higher `R` at every age, but a lower supply
        // ratio, so a lower burn fraction and with it a lower `C`. Which
        // wins depends on the curve; at ESF 22 per block the preserved
        // reward wins and the peak is on the dormant rail. It stays under
        // the structural cap, which is the property.
        assert_eq!(worst.0, 36_904_281, "the swept maximum moved");
        assert_eq!(
            worst.3, p.release_min,
            "the swept peak is on the dormant rail"
        );
    }

    /// The finding's scenario, pinned end to end: the honest YOUNG-CHAIN
    /// snapshot — raw genesis-condition tiers and their daemon-rounded
    /// forms (what the wallet actually receives) — must be well-formed.
    /// This is the bootstrap-operation guarantee: build, quote, and
    /// first-stake all ride this constructor from block 1.
    #[test]
    fn genesis_condition_snapshots_are_well_formed() {
        // The served tiers at genesis conditions (`C = 1`, `M = Zm`,
        // `R₀` = 1,024 SKL): `genesis_top_rung_anchors` in
        // `shekyl-economics` pins the top rung.
        ValidatedFeeEstimates::try_new(snapshot(34_133, 136_533, 6_826_666))
            .expect("genesis-condition tiers are honest and must pass");
    }
}
