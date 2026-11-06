// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Economics parameter snapshot + calibration stamp (PR 7 §5.3 R2 / §6.3 G5).
//!
//! [`EconomicsParametersSnapshot`] is the **rulebook** returned by
//! [`EconomicsEngine::parameters_snapshot`](super::traits::economics::EconomicsEngine::parameters_snapshot):
//! the resolved [`EconomicParams`](shekyl_economics::EconomicParams)
//! constants plus the staker-emission calibration consts,
//! tagged with a [`CalibrationStamp`] for staleness detection. It is
//! **not** a dashboard — time-varying derived state (live burn %,
//! release multiplier, effective emission share, annualized yield)
//! composes from the other three trait methods plus chain inputs, not
//! from this infallible constants method.
//!
//! # Why these types live in `shekyl-engine-core`, not `shekyl-economics`
//!
//! Historical: the snapshot once carried the claim-era tier table, whose
//! crate depended on `shekyl-economics`, so the composed type had to live
//! a level up. The tier table is retired; the snapshot stays here because
//! it is the engine's trait-surface type (`EconomicsEngine` is engine-core).
//! `ActivityMetric` and `shekyl_economics::params_digest` stay in
//! `shekyl-economics`.
//!
//! For the same reason the snapshot's staleness digest
//! ([`snapshot_calibration_digest`]) is computed **here**, not in
//! `shekyl-economics`: it is the engine's stamp over the rulebook.
//! The preimage is one version byte and `shekyl_economics::params_digest`.
//! Share and decay move the stamp because they are fields of that digest.
//! The version byte keeps the stamp off the bare sub-digest.
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

/// Format-version tag prefixed to the [`snapshot_calibration_digest`]
/// preimage. Bump on any change to the covered-field set, order, or
/// widths in that function's layout table — independent of
/// `shekyl_economics::DIGEST_FORMAT_VERSION` (the `EconomicParams`
/// sub-digest), which this preimage embeds as an opaque 32 bytes.
pub(crate) const SNAPSHOT_DIGEST_FORMAT_VERSION: u8 = 0x03;

/// Blake2b-256 over the calibration surface an
/// [`EconomicsParametersSnapshot`] exposes: a version tag and
/// [`params_digest`](shekyl_economics::params_digest).
///
/// `shekyl_economics::params_digest` covers every `EconomicParams`
/// field, including the staker-emission share, its decay and the
/// year length (ESR-16). Those used to be hashed beside the
/// sub-digest. They are fields now, so hashing them again would be a
/// second copy of one source. The version tag keeps this stamp from
/// collapsing onto the sub-digest.
///
/// # Canonical layout (format version `0x03`)
///
/// | Width            | Field                                                                |
/// |------------------|----------------------------------------------------------------------|
/// | 1                | format version tag ([`SNAPSHOT_DIGEST_FORMAT_VERSION`])               |
/// | 32               | `params_digest(params)` — the `EconomicParams` sub-digest            |
///
/// The share and the decay are fields of `params` (format `0x03` dropped
/// the trailing pair that restated them). The function is pure in its
/// argument. The claim-era tier table left the digest with the claim-era
/// retirement; the version tag keeps old and new digests disjoint.
pub(crate) fn snapshot_calibration_digest(params: &EconomicParams) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update([SNAPSHOT_DIGEST_FORMAT_VERSION]);
    hasher.update(params_digest(params));
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
pub(crate) struct CalibrationStamp {
    /// Monotonic calibration generation. Increments on each pre-genesis
    /// recalibration and (at V3.x) each adaptive-burn epoch. Consumers
    /// log it human-readably ("estimate from generation 7; current is
    /// 8") and treat a mismatch as "stale".
    pub generation: u32,

    /// Blake2b-256 of one version byte and
    /// [`params_digest`](shekyl_economics::params_digest)
    /// ([`snapshot_calibration_digest`]). Share and decay move the stamp
    /// because they are fields of that digest. The version byte keeps
    /// this stamp off the bare sub-digest. **Not** raw JSON bytes,
    /// **not** bincode. Catches a generation increment with no parameter
    /// change, and silent serialization drift that `generation` alone
    /// would miss.
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
pub(crate) struct EconomicsParametersSnapshot {
    /// Emission speed factor per block, for display. The curve reads
    /// [`shekyl_economics::EconomicParams::emission_speed_factor_per_block`].
    /// A factor above `u8::MAX` saturates; this field is not the shift.
    pub emission_speed_factor_per_block: u8,

    /// Total coin supply ceiling in atomic units (`2^32 · 10^9`).
    pub emission_curve_asymptote_atomic: u64,

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

    /// Calibration stamp for staleness detection (§6.3 G5).
    pub as_of: CalibrationStamp,
}
