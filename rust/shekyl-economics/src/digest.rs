//! Canonical [`EconomicParams`] digest (fixture lineage + snapshot
//! sub-digest).
//!
//! This Blake2b-256 over the ten `EconomicParams` fields is
//! **EconomicParams-scoped** and serves two roles:
//!
//! - the **C4 `RecordedChainFixture` lineage guard** — the committed
//!   fixture pins this digest, so a fixture produced under a different
//!   `EconomicParams` fails the staleness check; and
//! - the **EconomicParams leg** of `snapshot_calibration_digest`
//!   (`shekyl-engine-core`), which is what
//!   `CalibrationStamp.params_digest` actually stores.
//!
//! `CalibrationStamp.params_digest` is **not** this digest directly: it
//! is the full-surface `snapshot_calibration_digest`, which composes this
//! `EconomicParams` digest with the staker-emission constants and the
//! staking tier table (calibration values that live outside
//! `EconomicParams`). Keeping this function EconomicParams-only is
//! deliberate — the C4 fixtures depend only on `EconomicParams`, so their
//! lineage guard must not move when an unrelated calibration constant
//! changes. See `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §5.3 R2 /
//! §6.3 G5.
//!
//! # Why a hand-rolled canonical encoder
//!
//! The digest is the **calibration-drift detector**: two builds that
//! resolve `EconomicParams` to the same values must produce the same
//! 32-byte digest, on every platform and toolchain, forever. That
//! forecloses two serializers:
//!
//! - **Raw `economics_params.json` bytes** — JSON whitespace / key
//!   order / number formatting drift would change the digest without
//!   any parameter changing.
//! - **`bincode`** (rejected 2026-05-28, §5.3 R2 / §6.3 G5) — couples
//!   the digest to the `bincode` library version and risks
//!   cross-toolchain serialization drift (MSVC vs GCC integer layout
//!   incidents) at a calibration-critical surface.
//!
//! Instead this module serializes each field at a **fixed width, in a
//! fixed order, little-endian**, with a one-byte format-version tag,
//! then hashes the buffer with Blake2b-256. The layout is the contract;
//! it is documented here and exercised by [`params_digest`]'s
//! round-trip test and the C4 fixtures (which call this same function —
//! there is no second encoder).
//!
//! # Canonical byte layout (format version `0x02`)
//!
//! **`0x01` → `0x02` (Stage 3a):** the D2 escalation added
//! `escalation_knee_n` and `escalation_asymptote_share`. They are appended, so
//! every prior offset is unchanged — but appending is still a layout change, and
//! the whole point of the version tag is that a fixture produced under `0x01`
//! must **fail loudly** rather than silently match a preimage that no longer
//! covers every consensus-relevant parameter. The escalation numbers select the
//! staker/burn split, so a digest that omitted them would let two nodes agree on
//! a stale calibration stamp while computing different splits.
//!
//! The preimage is exactly **97 bytes** (`1` version tag + `12 × 8` u64
//! fields), hashed with `Blake2b<U32>`:
//!
//! | Offset | Width | Field                              | Notes               |
//! |--------|-------|------------------------------------|---------------------|
//! | 0      | 1     | format version tag                 | `0x02`              |
//! | 1      | 8     | `release_min`                      | u64 LE              |
//! | 9      | 8     | `release_max`                      | u64 LE              |
//! | 17     | 8     | `tx_volume_baseline`               | u64 LE              |
//! | 25     | 8     | `burn_base_rate`                   | u64 LE              |
//! | 33     | 8     | `burn_cap`                         | u64 LE              |
//! | 41     | 8     | `staker_pool_share`                | u64 LE              |
//! | 49     | 8     | `money_supply`                     | u64 LE              |
//! | 57     | 8     | `emission_speed_factor_per_minute` | u64 LE              |
//! | 65     | 8     | `final_subsidy_per_minute`         | u64 LE              |
//! | 73     | 8     | `daa_target_seconds`               | u64 LE              |
//! | 81     | 8     | `escalation_knee_n`                | u64 LE              |
//! | 89     | 8     | `escalation_asymptote_share`       | u64 LE              |
//!
//! The field order mirrors the [`EconomicParams`] struct declaration.
//! **Adding, removing, or reordering a field is a breaking layout
//! change** and must bump [`DIGEST_FORMAT_VERSION`] (so a stale fixture
//! produced under the old layout fails the staleness guard rather than
//! silently matching).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::params::EconomicParams;

/// Format-version tag prefixed to the digest preimage. Bump on any
/// change to the field set, order, or widths in the [module
/// docs](self) byte-layout table.
pub const DIGEST_FORMAT_VERSION: u8 = 0x02;

/// Length in bytes of the canonical digest preimage (`1` version tag +
/// `12 × 8` u64 fields = **97**). Exposed for the round-trip test's
/// fixed-buffer assertion.
///
/// **Kept honest by `preimage_length_matches_the_documented_layout`**, which
/// pins the literal so a field addition that changes this value fails a test
/// telling the author to update the byte-layout table in the module docs. In a
/// consensus digest spec, doc-vs-code drift is load-bearing: an implementer
/// building a second node from a stale table computes a different digest than
/// the running network, which is the exact failure the version tag exists to
/// prevent.
pub const DIGEST_PREIMAGE_LEN: usize = 1 + 12 * 8;

/// Serialize `params` to the canonical fixed-width little-endian
/// preimage documented in the [module docs](self).
///
/// Separated from the hash step so the round-trip test can assert the
/// exact byte layout independently of the Blake2b output.
fn canonical_preimage(params: &EconomicParams) -> [u8; DIGEST_PREIMAGE_LEN] {
    let mut buf = [0u8; DIGEST_PREIMAGE_LEN];
    buf[0] = DIGEST_FORMAT_VERSION;
    let mut off = 1;
    let mut put = |value: u64| {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
        off += 8;
    };
    put(params.release_min);
    put(params.release_max);
    put(params.tx_volume_baseline);
    put(params.burn_base_rate);
    put(params.burn_cap);
    put(params.staker_pool_share);
    put(params.money_supply);
    put(params.emission_speed_factor_per_minute);
    put(params.final_subsidy_per_minute);
    put(params.daa_target_seconds);
    put(params.escalation_knee_n);
    put(params.escalation_asymptote_share);
    debug_assert_eq!(off, DIGEST_PREIMAGE_LEN);
    buf
}

/// Blake2b-256 over the canonical [`EconomicParams`] byte layout.
///
/// This is the **single** canonical `EconomicParams` encoder, shared by
/// the C4 `RecordedChainFixture` lineage guard and the EconomicParams leg
/// of `snapshot_calibration_digest` (`shekyl-engine-core`) that
/// `CalibrationStamp.params_digest` stores. It is **not** the full
/// `CalibrationStamp` digest itself — that also covers the staker-emission
/// constants and the staking tier table. See the [module docs](self) for
/// the layout contract and the rejected alternatives (raw JSON, bincode).
#[must_use]
pub fn params_digest(params: &EconomicParams) -> [u8; 32] {
    let preimage = canonical_preimage(params);
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_layout_is_fixed_width_le() {
        let p = EconomicParams {
            release_min: 0x0102_0304_0506_0708,
            release_max: 0x1112_1314_1516_1718,
            tx_volume_baseline: 0x2122_2324_2526_2728,
            burn_base_rate: 0x3132_3334_3536_3738,
            burn_cap: 0x4142_4344_4546_4748,
            staker_pool_share: 0x5152_5354_5556_5758,
            money_supply: 0x6162_6364_6566_6768,
            emission_speed_factor_per_minute: 0x7172_7374_7576_7778,
            final_subsidy_per_minute: 0x8182_8384_8586_8788,
            daa_target_seconds: 0x9192_9394_9596_9798,
            escalation_knee_n: 0xA1A2_A3A4_A5A6_A7A8,
            escalation_asymptote_share: 0xB1B2_B3B4_B5B6_B7B8,
        };
        let buf = canonical_preimage(&p);
        assert_eq!(buf[0], DIGEST_FORMAT_VERSION);
        // release_min at offset 1, little-endian.
        assert_eq!(&buf[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
        // daa_target_seconds is the last field at offset 73.
        assert_eq!(&buf[73..81], &0x9192_9394_9596_9798u64.to_le_bytes());
    }

    #[test]
    fn digest_is_deterministic() {
        let p = EconomicParams::default();
        assert_eq!(params_digest(&p), params_digest(&p));
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let base = EconomicParams::default();
        let mut bumped = base.clone();
        bumped.burn_cap += 1;
        assert_ne!(params_digest(&base), params_digest(&bumped));
    }

    #[test]
    fn digest_round_trips_through_preimage() {
        let p = EconomicParams::default();
        let preimage = canonical_preimage(&p);
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(preimage);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(params_digest(&p), expected);
    }
    /// **The byte-layout table in the module docs is part of the consensus
    /// contract, so it gets a test.**
    ///
    /// F-DIGEST (PR #373 review): the `0x01` → `0x02` bump updated the version
    /// constant and appended two table rows but left the header's byte count and
    /// the table's version cell stale — three numbers disagreeing in the spec for
    /// a consensus digest. The code was right and the fixture regen proved it,
    /// but an implementer building a second node from the stale table would have
    /// computed a different digest than the running network. That is precisely
    /// the failure the version tag exists to prevent, arriving through the
    /// documentation instead of the code.
    ///
    /// Pinning the literal converts that silent drift into a failing test whose
    /// message names the obligation: change the layout, update the table.
    #[test]
    fn preimage_length_matches_the_documented_layout() {
        const DOCUMENTED_FIELDS: usize = 12;
        const DOCUMENTED_LEN: usize = 97;

        assert_eq!(
            DIGEST_PREIMAGE_LEN, DOCUMENTED_LEN,
            "preimage length changed — update the byte-layout table in the module \
             docs (header byte count, the version cell, and the offset rows), then \
             this literal, and bump DIGEST_FORMAT_VERSION"
        );
        assert_eq!(
            DIGEST_PREIMAGE_LEN,
            1 + DOCUMENTED_FIELDS * 8,
            "the documented field count no longer explains the preimage length"
        );

        // The last documented offset plus its width must land exactly on the end.
        const LAST_FIELD_OFFSET: usize = 89; // escalation_asymptote_share
        assert_eq!(
            LAST_FIELD_OFFSET + 8,
            DIGEST_PREIMAGE_LEN,
            "the table's final row does not end at the preimage boundary"
        );

        // And the tag the table advertises is the one actually written.
        let buf = canonical_preimage(&EconomicParams::default());
        assert_eq!(buf.len(), DOCUMENTED_LEN);
        assert_eq!(
            buf[0], 0x02,
            "the byte-layout table advertises 0x02; the encoder must write it"
        );
    }
}
