// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee lattice: a paid fee is a whole multiple of
//! [`FEE_QUANTIZATION_MASK`] atomic units.
//!
//! One constant, one rounding function, two callers: relay admission
//! ([`super::relay_floor_admits`]) and the wallet's fee arithmetic
//! (`shekyl_rpc_client::tx_fee`). The daemon does not serve the lattice
//! (FL-R27): a daemon serving its own would put its wallets' fees on a
//! lattice of its choosing, a per-daemon fingerprint (FL-C1). It is relay
//! policy, not chain identity, so it is a Rust constant and not a
//! `config/economics_params.json` entry.

use shekyl_units::DISPLAY_DECIMAL_POINT;

/// Decimal places a fee is quoted to, in SKL: the lattice step is
/// `10^-FEE_DECIMAL_PLACES` SKL.
pub const FEE_DECIMAL_PLACES: u32 = 6;

const _: () = assert!(
    FEE_DECIMAL_PLACES <= DISPLAY_DECIMAL_POINT as u32,
    "the fee lattice cannot be finer than the atomic unit"
);

/// Atomic units per lattice step:
/// `10^(DISPLAY_DECIMAL_POINT − FEE_DECIMAL_PLACES)`.
pub const FEE_QUANTIZATION_MASK: u64 = 10u64.pow(DISPLAY_DECIMAL_POINT as u32 - FEE_DECIMAL_PLACES);

/// `weight × rate_per_weight`, rounded up to `mask`. `None` when the
/// product or the rounding leaves `u64`, or when `mask` is zero: a
/// requirement no fee can state.
///
/// [`quantized_fee`] is this on the shipped mask. A [`crate::RelayPolicy`]
/// passes the mask its decimal places select.
#[must_use]
pub(crate) const fn quantize_to_mask(weight: u64, rate_per_weight: u64, mask: u64) -> Option<u64> {
    match weight.checked_mul(rate_per_weight) {
        Some(raw) => raw.checked_next_multiple_of(mask),
        None => None,
    }
}

/// `weight × rate_per_weight`, rounded up to the shipped lattice.
/// `None` when the product or the rounding leaves `u64`.
#[must_use]
pub const fn quantized_fee(weight: u64, rate_per_weight: u64) -> Option<u64> {
    quantize_to_mask(weight, rate_per_weight, FEE_QUANTIZATION_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lattice_is_one_thousand_atomic_units() {
        assert_eq!(DISPLAY_DECIMAL_POINT, 9, "an atomic unit is 10^-9 SKL");
        assert_eq!(FEE_QUANTIZATION_MASK, 1_000);
    }

    #[test]
    fn a_fee_is_rounded_up_to_the_next_lattice_step() {
        assert_eq!(quantized_fee(0, 333), Some(0));
        assert_eq!(quantized_fee(1, 1), Some(1_000));
        assert_eq!(quantized_fee(11_097, 333), Some(3_696_000));
        assert_eq!(quantized_fee(3_000, 1_000), Some(3_000_000));
        assert_eq!(quantized_fee(3_000, 1_001), Some(3_003_000));
    }

    #[test]
    fn an_unrepresentable_requirement_is_none() {
        assert_eq!(quantized_fee(u64::MAX, 2), None);
        assert_eq!(
            quantized_fee(u64::MAX, 1),
            None,
            "the rounding itself overflows"
        );
        assert_eq!(
            quantized_fee(u64::MAX / FEE_QUANTIZATION_MASK, FEE_QUANTIZATION_MASK),
            Some(u64::MAX / FEE_QUANTIZATION_MASK * FEE_QUANTIZATION_MASK)
        );
    }
}
