// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Economics parameter snapshot + calibration stamp (PR 7 §5.3 R2 / §6.3 G5).
//!
//! [`EconomicsParametersSnapshot`] is the **rulebook** returned by
//! [`EconomicsEngine::parameters_snapshot`](super::traits::economics::EconomicsEngine::parameters_snapshot):
//! the resolved [`EconomicParams`](shekyl_economics::EconomicParams)
//! constants plus the staking [`TierTable`](shekyl_staking::TierTable),
//! tagged with a [`CalibrationStamp`] for staleness detection. It is
//! **not** a dashboard — time-varying derived state (live burn %,
//! release multiplier, effective emission share, annualized yield)
//! composes from the other three trait methods plus chain inputs, not
//! from this infallible constants method.
//!
//! # Why these types live in `shekyl-engine-core`, not `shekyl-economics`
//!
//! The snapshot carries [`shekyl_staking::TierTable`]. `shekyl-staking`
//! depends on `shekyl-economics`, so placing the snapshot in
//! `shekyl-economics` would invert that dependency. `shekyl-engine-core`
//! depends on both, so it is the natural home for the composed type.
//! `ActivityMetric` and `shekyl_economics::params_digest` (which have no
//! staking dependency) stay in `shekyl-economics`.
//!
//! For the same reason the snapshot's staleness digest
//! ([`snapshot_calibration_digest`]) is computed **here**, not in
//! `shekyl-economics`: it must cover every calibration value the snapshot
//! displays, and the tier table is only visible from `shekyl-engine-core`.
//! `shekyl_economics::params_digest` covers `EconomicParams` alone (and
//! backs the C4 fixture lineage guard, whose tested emission/burn values
//! depend only on `EconomicParams`); the snapshot additionally surfaces the
//! staker-emission share/decay and the tier table, so its stamp folds those
//! in on top of the `EconomicParams` sub-digest.
//!
//! # No-cache discipline (§6.3 G5)
//!
//! Consumers **must not** cache a snapshot beyond immediate use; capture
//! it at the start of a logical operation if needed. A cached snapshot
//! goes stale relative to a later calibration generation (config rebuild
//! at V3.0; adaptive-burn epoch at V3.x). The [`CalibrationStamp`] is the
//! detection surface: compare [`CalibrationStamp::generation`] (cheap,
//! human-readable) and, if equal, [`CalibrationStamp::params_digest`]
//! (bit-exact). A `generation` mismatch means a real recalibration; a
//! `generation` match with a `params_digest` mismatch is a build-system
//! integrity signal (not an attack vector at V3.0).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use shekyl_economics::{params_digest, EconomicParams};
use shekyl_staking::TierTable;

/// Format-version tag prefixed to the [`snapshot_calibration_digest`]
/// preimage. Bump on any change to the covered-field set, order, or
/// widths in that function's layout table — independent of
/// `shekyl_economics::DIGEST_FORMAT_VERSION` (the `EconomicParams`
/// sub-digest), which this preimage embeds as an opaque 32 bytes.
pub(crate) const SNAPSHOT_DIGEST_FORMAT_VERSION: u8 = 0x01;

/// Blake2b-256 over the **full calibration surface an
/// [`EconomicsParametersSnapshot`] exposes** — not merely `EconomicParams`.
///
/// `shekyl_economics::params_digest` covers the ten `EconomicParams`
/// fields and backs the C4 fixture lineage guard (whose tested
/// emission/burn values depend only on `EconomicParams`). The snapshot,
/// however, also surfaces the staker-emission share/decay
/// (`shekyl-economics` calibration consts) and the staking tier table
/// (`shekyl-staking`) — all driven by `config/economics_params.json`. A
/// stamp that hashed only `EconomicParams` would **false-accept** a
/// snapshot after one of those changed without a
/// [`CALIBRATION_GENERATION`](shekyl_economics::CALIBRATION_GENERATION)
/// bump, which (being a hand-maintained constant) is exactly the human
/// error the digest backstops. This digest therefore folds every
/// calibration value the snapshot displays.
///
/// # Canonical layout (format version `0x01`)
///
/// | Width            | Field                                                                |
/// |------------------|----------------------------------------------------------------------|
/// | 1                | format version tag ([`SNAPSHOT_DIGEST_FORMAT_VERSION`])               |
/// | 32               | `params_digest(params)` — the `EconomicParams` sub-digest            |
/// | 8                | `staker_emission_share` u64 LE                                       |
/// | 8                | `staker_emission_decay` u64 LE                                       |
/// | 3 × (1 + 8 + 8)  | per tier in `TierTable` order: `id` u8, `lock_blocks` u64 LE, `yield_multiplier` u64 LE |
///
/// Tier `name` is descriptive, not a calibration value, and is omitted.
/// The function is pure in its arguments (no global reads) so the
/// coverage tests can vary each input independently.
pub(crate) fn snapshot_calibration_digest(
    params: &EconomicParams,
    staker_emission_share: u64,
    staker_emission_decay: u64,
    tiers: &TierTable,
) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update([SNAPSHOT_DIGEST_FORMAT_VERSION]);
    hasher.update(params_digest(params));
    hasher.update(staker_emission_share.to_le_bytes());
    hasher.update(staker_emission_decay.to_le_bytes());
    for tier in tiers {
        hasher.update([tier.id]);
        hasher.update(tier.lock_blocks.to_le_bytes());
        hasher.update(tier.yield_multiplier.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Staleness-detection stamp attached to an
/// [`EconomicsParametersSnapshot`]. Two formally-independent surfaces
/// (§6.3 G5): [`Self::generation`] (configuration epoch) and
/// [`Self::params_digest`] (bit-exact content hash). At V3.0
/// `generation` is **not** a chain height — there is no
/// `generation_active_at(height)`; binding calibration to heights is a
/// V3.x adaptive-burn FOLLOWUPS item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// R6: only constructed via `parameters_snapshot`, which has zero V3.0 consumer (§5.5).
#[allow(dead_code)]
pub(crate) struct CalibrationStamp {
    /// Monotonic calibration generation. Increments on each pre-genesis
    /// recalibration and (at V3.x) each adaptive-burn epoch. Consumers
    /// log it human-readably ("estimate from generation 7; current is
    /// 8") and treat a mismatch as "stale".
    pub generation: u32,

    /// Blake2b-256 over the **full calibration surface this snapshot
    /// exposes** (see [`snapshot_calibration_digest`]): the
    /// [`EconomicParams`](shekyl_economics::EconomicParams) sub-digest
    /// **plus** the staker-emission share/decay and the staking tier
    /// table. **Not** raw JSON bytes, **not** bincode. Covering only
    /// `EconomicParams` (as `shekyl_economics::params_digest` does, for
    /// the C4 fixture lineage) would false-accept a snapshot whose staker
    /// or tier calibration changed without a `generation` bump. Catches a
    /// generation increment with no parameter change, and silent
    /// serialization drift that `generation` alone would miss.
    pub params_digest: [u8; 32],
}

/// Resolved economic rulebook for governance / display (PR 7 §5.3 R2).
///
/// All values are **base** constants from the build-time
/// [`EconomicParams`](shekyl_economics::EconomicParams) loader, in
/// integer units (basis points / milli-units / atomic units) — no
/// floats, matching the consensus no-float discipline. Effective
/// height-varying quantities (decayed emission share, live burn) are
/// **not** here; the consumer composes them from the other trait
/// methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// R6: only constructed via `parameters_snapshot`, which has zero V3.0 consumer (§5.5).
#[allow(dead_code)]
pub(crate) struct EconomicsParametersSnapshot {
    /// Emission speed factor per minute (locked at 22).
    pub emission_speed_factor: u8,

    /// Total coin supply ceiling in atomic units (`2^32 · 10^9`).
    pub money_supply_atomic: u64,

    /// Tail subsidy floor per minute in atomic units (300_000_000;
    /// the JSON authority, not the Monero-era `3 × 10¹¹` reference in
    /// `DESIGN_CONCEPTS.md` §2).
    pub final_subsidy_per_minute: u64,

    /// Transaction-volume baseline for the release multiplier and burn
    /// volume ratio.
    pub tx_volume_baseline: u64,

    /// Release multiplier floor in milli-units (e.g. `800` → `0.800×`).
    pub release_min_milli: u32,

    /// Release multiplier ceiling in milli-units (e.g. `1300` → `1.300×`).
    pub release_max_milli: u32,

    /// Base burn-rate coefficient in basis points.
    pub burn_base_rate_bp: u16,

    /// Burn-rate cap in basis points.
    pub burn_cap_bp: u16,

    /// Staker share of the burned fee pool in basis points.
    pub staker_fee_pool_share_bp: u16,

    /// **Base** staker emission share in basis points — **not** the
    /// decayed effective share (which is height-varying; the consumer
    /// applies the decay).
    pub staker_emission_share_bp: u16,

    /// Per-year staker emission decay factor in milli-units (e.g. `900`
    /// → `0.900/year`).
    pub staker_emission_decay_milli: u16,

    /// Staking tier table read by reference from `shekyl-staking` — not
    /// redefined here (single source of truth for tier parameters).
    pub tiers: TierTable,

    /// Calibration stamp for staleness detection (§6.3 G5).
    pub as_of: CalibrationStamp,
}
