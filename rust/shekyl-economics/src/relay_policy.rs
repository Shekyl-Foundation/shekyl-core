// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Relay policy: the admission lookback, its slack, the fee lattice's
//! decimal places, the ladder's reference weight and rung ratios, and the
//! emission-claim hold, generated from `config/relay_policy.json` (its own
//! file: the file boundary is the digest boundary, ruled 2026-10-29).
//!
//! These select what a node relays. They are not chain identity
//! ([`crate::params::EconomicParams`] is), so they stay out of the
//! consensus digest (FL-R27). [`relay_policy`] is the shipped policy.
//! A fold that varies one builds its own [`RelayPolicy`], passes it
//! through [`RelayPolicy::validate`] (deserializing one does so itself),
//! and calls [`RelayPolicy::admits`], [`RelayPolicy::quantize`] or
//! [`RelayPolicy::admitted_floor`]. [`relay_policy_digest`] names a policy
//! in a report; it is a label, which nothing checks and no chain carries.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use shekyl_units::DISPLAY_DECIMAL_POINT;

use crate::fee::quantization::quantize_to_mask;
use crate::fee::{
    EMISSION_CLAIM_FEE_FLOOR, FEE_DECIMAL_PLACES, RELAY_ADMISSION_SLACK_BP, RELAY_FLOOR_LOOKBACK,
    RELAY_FLOOR_REFERENCE_TX_WEIGHT, STANDARD_RUNG_OVER_ECONOMY,
};
use crate::params::GENERATED_PRIORITY_RUNG_FACTOR;

/// Basis points in one whole. [`RelayPolicy::admission_slack_bp`] is
/// written in these. A slack at or above this admits at zero.
pub const BASIS_POINTS: u32 = 10_000;

/// The relay numbers a node admits and quotes with.
///
/// Deserializes only through [`Self::validate`] (`try_from` a wire form
/// with the same fields), as [`crate::EconomicParams`] does: there is no
/// way to deserialize a policy its readers cannot use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RelayPolicyWire")]
pub struct RelayPolicy {
    /// Lookback depth `G`, in blocks.
    pub lookback: u64,
    /// Admission slack, basis points ([`BASIS_POINTS`] is one whole). The
    /// shipped value is zero.
    pub admission_slack_bp: u32,
    /// Decimal places the fee lattice keeps.
    pub fee_decimal_places: u32,
    /// The emission-claim hold, in atomic units: the claim leg's priced
    /// weight at the genesis Economy rung, on the shipped lattice.
    pub emission_claim_fee_floor: u64,
    /// `w_ref`, the weight the relay floor and every rung fold in
    /// (`F = R·C·w_ref/M²`). Relay policy until EUP-5 D rules on the floor;
    /// if D puts the floor into consensus, D's PR moves it into
    /// [`crate::EconomicParams`] with a digest bump.
    pub ref_tx_weight: u64,
    /// Standard over the Economy rung (the relay floor). Same line as
    /// [`Self::ref_tx_weight`].
    pub standard_over_economy: u64,
    /// Priority's factor: Priority is `max(factor·R·C/M, Standard)`. Same
    /// line as [`Self::ref_tx_weight`].
    pub priority_factor: u64,
}

impl RelayPolicy {
    /// The policy production admits, quotes and holds with, generated from
    /// `config/relay_policy.json`; this value is what readers use.
    ///
    /// `lookback` is [`RELAY_FLOOR_LOOKBACK`], a `usize` of 5.
    // CLIPPY: cast_possible_truncation — usize-to-u64 loses bits only on a
    // 128-bit target this tree does not build. The depth is 5.
    #[allow(clippy::cast_possible_truncation)]
    pub const SHIPPED: Self = Self {
        lookback: RELAY_FLOOR_LOOKBACK as u64,
        admission_slack_bp: RELAY_ADMISSION_SLACK_BP,
        fee_decimal_places: FEE_DECIMAL_PLACES,
        emission_claim_fee_floor: EMISSION_CLAIM_FEE_FLOOR,
        ref_tx_weight: RELAY_FLOOR_REFERENCE_TX_WEIGHT,
        standard_over_economy: STANDARD_RUNG_OVER_ECONOMY,
        priority_factor: GENERATED_PRIORITY_RUNG_FACTOR,
    };

    /// Atomic units per lattice step, `10^(DISPLAY_DECIMAL_POINT − places)`.
    ///
    /// `None` when the places are finer than an atomic unit: that lattice
    /// cannot be stated.
    #[must_use]
    pub const fn quantization_mask(self) -> Option<u64> {
        if self.fee_decimal_places > DISPLAY_DECIMAL_POINT as u32 {
            None
        } else {
            Some(10u64.pow(DISPLAY_DECIMAL_POINT as u32 - self.fee_decimal_places))
        }
    }

    /// `weight × rate`, rounded up to this policy's lattice.
    ///
    /// `None` when the mask cannot be stated, or when the product or the
    /// rounding leaves `u64`. The shipped mask is
    /// [`crate::FEE_QUANTIZATION_MASK`].
    #[must_use]
    pub const fn quantize(self, weight: u64, rate: u64) -> Option<u64> {
        match self.quantization_mask() {
            Some(mask) => quantize_to_mask(weight, rate, mask),
            None => None,
        }
    }

    /// `floor` reduced by [`Self::admission_slack_bp`] basis points.
    ///
    /// Slack of zero is `floor`. A slack at or above [`BASIS_POINTS`]
    /// is zero: the reduction saturates rather than wrapping. The
    /// result is at most `floor`, so it fits `u64`.
    #[must_use]
    pub fn admitted_floor(self, floor: u64) -> u64 {
        let floor_wide = u128::from(floor);
        let reduction = floor_wide.saturating_mul(u128::from(self.admission_slack_bp))
            / u128::from(BASIS_POINTS);
        let admitted = floor_wide.saturating_sub(reduction);
        u64::try_from(admitted).expect("slack reduced a floor above the floor it started from")
    }

    /// Admit iff `fee` meets the quantized minimum floor, less this
    /// policy's slack.
    ///
    /// Empty `floors` refuses: no floor is not a floor of zero. A
    /// requirement the lattice cannot state refuses: no fee can meet it.
    /// Only the minimum floor is read, so order carries no meaning.
    #[must_use]
    pub fn admits(self, fee: u64, weight: u64, floors: &[u64]) -> bool {
        let Some(&min_floor) = floors.iter().min() else {
            return false;
        };
        let Some(needed) = self.quantize(weight, min_floor) else {
            return false;
        };
        u128::from(fee) >= u128::from(self.admitted_floor(needed))
    }
}

/// Why [`RelayPolicy::validate`] refused a policy: each names what the
/// policy's own reader would do with the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayPolicyError {
    /// The lattice keeps more decimals than an atomic unit has:
    /// [`RelayPolicy::quantization_mask`] is `None`, and
    /// [`RelayPolicy::admits`] refuses every fee.
    #[error("fee_decimal_places {places} is finer than an atomic unit ({max} places)")]
    LatticeFinerThanAtomic {
        /// The refused decimals.
        places: u32,
        /// [`DISPLAY_DECIMAL_POINT`].
        max: u32,
    },
    /// A slack past one whole admits at zero exactly as one whole does, so
    /// two values would name one policy.
    #[error("relay_admission_slack_bp {slack} is past one whole ({BASIS_POINTS})")]
    SlackPastWhole {
        /// The refused slack.
        slack: u32,
    },
    /// `w_ref = 0` prices the floor `R·C·w_ref/M²` at zero, which the
    /// floor's `max(1)` turns into one atomic unit: no floor.
    #[error("relay_floor_reference_tx_weight is zero: the relay floor would be one atomic unit")]
    ReferenceWeightZero,
    /// Standard at zero times Economy is below the relay floor, so a
    /// wallet quoting Standard would be refused.
    #[error("standard_rung_over_economy is zero: Standard would sit below the relay floor")]
    StandardBelowEconomy,
}

impl RelayPolicy {
    /// Refuse a policy its readers cannot use; see [`RelayPolicyError`].
    /// The shipped policy passes (a test holds it), and so does a lattice
    /// of eight decimals (E16-9's).
    ///
    /// # Errors
    ///
    /// The first clause the policy breaks, in [`RelayPolicyError`]'s order.
    pub const fn validate(&self) -> Result<(), RelayPolicyError> {
        if self.quantization_mask().is_none() {
            return Err(RelayPolicyError::LatticeFinerThanAtomic {
                places: self.fee_decimal_places,
                max: DISPLAY_DECIMAL_POINT as u32,
            });
        }
        if self.admission_slack_bp > BASIS_POINTS {
            return Err(RelayPolicyError::SlackPastWhole {
                slack: self.admission_slack_bp,
            });
        }
        if self.ref_tx_weight == 0 {
            return Err(RelayPolicyError::ReferenceWeightZero);
        }
        if self.standard_over_economy == 0 {
            return Err(RelayPolicyError::StandardBelowEconomy);
        }
        Ok(())
    }
}

/// [`RelayPolicy`]'s serde wire: the same fields, converted through
/// [`RelayPolicy::validate`]. The conversion names every field, so the
/// compiler holds the two field lists equal.
#[derive(Deserialize)]
#[serde(rename = "RelayPolicy", deny_unknown_fields)]
struct RelayPolicyWire {
    lookback: u64,
    admission_slack_bp: u32,
    fee_decimal_places: u32,
    emission_claim_fee_floor: u64,
    ref_tx_weight: u64,
    standard_over_economy: u64,
    priority_factor: u64,
}

impl TryFrom<RelayPolicyWire> for RelayPolicy {
    type Error = RelayPolicyError;

    fn try_from(w: RelayPolicyWire) -> Result<Self, Self::Error> {
        let policy = Self {
            lookback: w.lookback,
            admission_slack_bp: w.admission_slack_bp,
            fee_decimal_places: w.fee_decimal_places,
            emission_claim_fee_floor: w.emission_claim_fee_floor,
            ref_tx_weight: w.ref_tx_weight,
            standard_over_economy: w.standard_over_economy,
            priority_factor: w.priority_factor,
        };
        policy.validate()?;
        Ok(policy)
    }
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self::SHIPPED
    }
}

/// Format byte of [`relay_policy_digest`]'s preimage. A change to the
/// preimage's layout moves it.
pub const RELAY_DIGEST_FORMAT_VERSION: u8 = 0x01;

/// Length of [`relay_policy_digest`]'s preimage: the format byte and the
/// seven fields, each as a little-endian `u64`, in declaration order.
pub const RELAY_DIGEST_PREIMAGE_LEN: usize = 1 + 7 * 8;

fn relay_preimage(policy: &RelayPolicy) -> [u8; RELAY_DIGEST_PREIMAGE_LEN] {
    let mut buf = [0u8; RELAY_DIGEST_PREIMAGE_LEN];
    buf[0] = RELAY_DIGEST_FORMAT_VERSION;
    let mut off = 1;
    let mut put = |value: u64| {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
        off += 8;
    };
    put(policy.lookback);
    put(u64::from(policy.admission_slack_bp));
    put(u64::from(policy.fee_decimal_places));
    put(policy.emission_claim_fee_floor);
    put(policy.ref_tx_weight);
    put(policy.standard_over_economy);
    put(policy.priority_factor);
    debug_assert_eq!(off, RELAY_DIGEST_PREIMAGE_LEN);
    buf
}

/// Blake2b-256 over a [`RelayPolicy`]'s fixed-width preimage: the label a
/// report prints beside [`crate::params_digest`] and the consensus digest,
/// so a reader can tell which policy a figure was folded under. Not chain
/// identity: no block, peer or wallet compares it.
#[must_use]
pub fn relay_policy_digest(policy: &RelayPolicy) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(relay_preimage(policy));
    hasher.finalize().into()
}

/// The shipped [`RelayPolicy`].
#[must_use]
pub fn relay_policy() -> &'static RelayPolicy {
    &RelayPolicy::SHIPPED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_policy_is_the_relay_constants() {
        let policy = RelayPolicy::SHIPPED;
        assert_eq!(policy.lookback, 5);
        assert_eq!(policy.admission_slack_bp, 0);
        assert_eq!(BASIS_POINTS, 10_000);
        assert_eq!(policy.fee_decimal_places, 6);
        // Derived (E16-8; recomputed by shekyl-engine-core's
        // `the_claim_hold_is_the_genesis_economy_fee_at_the_priced_weight`).
        assert_eq!(policy.emission_claim_fee_floor, 1_398_068_000);
        assert_eq!(policy.ref_tx_weight, 3_000);
        assert_eq!(policy.standard_over_economy, 4);
        assert_eq!(policy.priority_factor, 2);
        assert_eq!(RelayPolicy::default(), policy);
        assert_eq!(*relay_policy(), policy);
        assert_eq!(policy.quantization_mask(), Some(1_000));
        assert_eq!(policy.quantize(1, 1), Some(1_000));
        assert_eq!(policy.admitted_floor(100_000), 100_000);
    }

    /// The shipped policy and E16-9's eight-decimal lattice pass; one value
    /// per clause is refused, by that clause, through both doors.
    #[test]
    fn the_validator_refuses_one_value_per_clause() {
        let shipped = RelayPolicy::SHIPPED;
        assert_eq!(shipped.validate(), Ok(()));
        let eight = RelayPolicy {
            fee_decimal_places: 8,
            ..shipped
        };
        assert_eq!(eight.validate(), Ok(()));
        let whole = RelayPolicy {
            admission_slack_bp: BASIS_POINTS,
            ..shipped
        };
        assert_eq!(whole.validate(), Ok(()));
        let max = u32::from(DISPLAY_DECIMAL_POINT);
        for (policy, refused) in [
            (
                RelayPolicy {
                    fee_decimal_places: max + 1,
                    ..shipped
                },
                RelayPolicyError::LatticeFinerThanAtomic {
                    places: max + 1,
                    max,
                },
            ),
            (
                RelayPolicy {
                    admission_slack_bp: BASIS_POINTS + 1,
                    ..shipped
                },
                RelayPolicyError::SlackPastWhole {
                    slack: BASIS_POINTS + 1,
                },
            ),
            (
                RelayPolicy {
                    ref_tx_weight: 0,
                    ..shipped
                },
                RelayPolicyError::ReferenceWeightZero,
            ),
            (
                RelayPolicy {
                    standard_over_economy: 0,
                    ..shipped
                },
                RelayPolicyError::StandardBelowEconomy,
            ),
        ] {
            assert_eq!(policy.validate(), Err(refused));
            let wire = serde_json::to_value(policy).expect("a policy serializes");
            let err = serde_json::from_value::<RelayPolicy>(wire)
                .expect_err("the serde door refuses what validate refuses");
            assert_eq!(err.to_string(), refused.to_string());
        }
        // The door round-trips the shipped policy and refuses a name it
        // does not have.
        let wire = serde_json::to_value(shipped).expect("serializes");
        assert_eq!(
            serde_json::from_value::<RelayPolicy>(wire.clone()).expect("round-trips"),
            shipped
        );
        let mut unknown = wire;
        unknown
            .as_object_mut()
            .expect("an object")
            .insert("lookback_blocks".into(), 5.into());
        assert!(serde_json::from_value::<RelayPolicy>(unknown).is_err());
    }

    /// The relay digest is pinned at the shipped policy, and each field
    /// moves it: a label that ignored a field could not tell two policies
    /// apart.
    #[test]
    fn the_relay_digest_is_pinned_and_hears_every_field() {
        let shipped = RelayPolicy::SHIPPED;
        let hex: String = relay_policy_digest(&shipped)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, RELAY_DIGEST_PIN);
        let pre = relay_preimage(&shipped);
        assert_eq!(pre.len(), 57);
        assert_eq!(pre[0], RELAY_DIGEST_FORMAT_VERSION);
        assert_eq!(&pre[1..9], &5u64.to_le_bytes());
        assert_eq!(&pre[49..57], &2u64.to_le_bytes());
        let moved = [
            RelayPolicy {
                lookback: 6,
                ..shipped
            },
            RelayPolicy {
                admission_slack_bp: 1,
                ..shipped
            },
            RelayPolicy {
                fee_decimal_places: 7,
                ..shipped
            },
            RelayPolicy {
                emission_claim_fee_floor: 1,
                ..shipped
            },
            RelayPolicy {
                ref_tx_weight: 1,
                ..shipped
            },
            RelayPolicy {
                standard_over_economy: 5,
                ..shipped
            },
            RelayPolicy {
                priority_factor: 3,
                ..shipped
            },
        ];
        for policy in moved {
            assert_ne!(
                relay_policy_digest(&policy),
                relay_policy_digest(&shipped),
                "{policy:?}"
            );
        }
    }

    const RELAY_DIGEST_PIN: &str =
        "5f19950d8d031d0efa1f8e09f06d92c3b9a357175a9685ab7bd7fd49b45cc6b2";

    #[test]
    fn an_alternative_policy_changes_the_lattice_and_the_slack() {
        let shipped = RelayPolicy::SHIPPED;
        let finer = RelayPolicy {
            fee_decimal_places: 8,
            ..shipped
        };
        assert_eq!(finer.quantization_mask(), Some(10));
        assert_eq!(finer.quantize(1, 1), Some(10));
        assert_ne!(finer.quantize(1, 1), shipped.quantize(1, 1));

        let open = RelayPolicy {
            admission_slack_bp: BASIS_POINTS,
            ..shipped
        };
        assert_eq!(open.admitted_floor(100_000), 0);
        assert!(open.admits(0, 1_000, &[100]));
        assert!(!shipped.admits(0, 1_000, &[100]));

        let too_fine = RelayPolicy {
            fee_decimal_places: u32::from(DISPLAY_DECIMAL_POINT) + 1,
            ..shipped
        };
        assert_eq!(too_fine.quantization_mask(), None);
        assert!(!too_fine.admits(u64::MAX, 1, &[1]));
        assert!(!shipped.admits(0, 1, &[]));
    }
}
