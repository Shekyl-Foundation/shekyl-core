//! Canonical [`EconomicParams`] digest for [`CalibrationStamp`].
//!
//! [`CalibrationStamp`]: the `params_digest` field surfaced through
//! `EconomicsParametersSnapshot` (`shekyl-engine-core`); see
//! `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §5.3 R2 / §6.3 G5.
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
//! # Canonical byte layout (format version `0x01`)
//!
//! The preimage is exactly **81 bytes**, hashed with `Blake2b<U32>`:
//!
//! | Offset | Width | Field                              | Notes               |
//! |--------|-------|------------------------------------|---------------------|
//! | 0      | 1     | format version tag                 | `0x01`              |
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
pub const DIGEST_FORMAT_VERSION: u8 = 0x01;

/// Length in bytes of the canonical digest preimage (`1` version tag +
/// `10 × 8` u64 fields). Exposed for the round-trip test's
/// fixed-buffer assertion.
pub const DIGEST_PREIMAGE_LEN: usize = 1 + 10 * 8;

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
    debug_assert_eq!(off, DIGEST_PREIMAGE_LEN);
    buf
}

/// Blake2b-256 over the canonical [`EconomicParams`] byte layout.
///
/// This is the **single** canonical encoder shared between the
/// `CalibrationStamp` runtime path (C1) and the `RecordedChainFixture`
/// staleness guard (C4). See the [module docs](self) for the layout
/// contract and the rejected alternatives (raw JSON, bincode).
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
}
