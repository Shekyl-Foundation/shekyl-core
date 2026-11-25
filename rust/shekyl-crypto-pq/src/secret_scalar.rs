// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Decoding a secret scalar with no unwiped copy of its bytes (rule 35).
//!
//! `Scalar::from_canonical_bytes` takes its array by value, so every
//! `from_canonical_bytes(*secret)` leaves a copy of the secret on the stack
//! that nothing wipes. Each decode of secret bytes in this crate comes here.

use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The scalar `encoded` is the canonical encoding of, or `None` when it is
/// not canonical. The caller names what that means for its secret.
///
/// The encoding is copied into zeroizing scratch and reduced through the
/// borrowing wide reduction. An encoding is canonical exactly when reducing
/// it changes nothing, which is compared in constant time.
#[must_use]
pub(crate) fn canonical_secret_scalar(encoded: &[u8; 32]) -> Option<Zeroizing<Scalar>> {
    let mut wide = Zeroizing::new([0u8; 64]);
    wide[..encoded.len()].copy_from_slice(encoded);
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    bool::from(scalar.as_bytes().ct_eq(encoded)).then_some(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decode agrees with the library's: the same scalar for canonical
    /// encodings, and a refusal of the group order, the encoding after it and
    /// all-ones. Red edit: drop the comparison, and a reduced encoding passes.
    #[test]
    fn a_secret_decodes_only_from_its_canonical_encoding() {
        let order_minus_one = (-Scalar::ONE).to_bytes();
        for canonical in [[0u8; 32], Scalar::ONE.to_bytes(), order_minus_one] {
            let decoded = canonical_secret_scalar(&canonical).expect("canonical");
            let library: Scalar =
                Option::from(Scalar::from_canonical_bytes(canonical)).expect("canonical");
            assert_eq!(*decoded, library);
        }
        let mut order = order_minus_one;
        order[0] += 1;
        let mut past_order = order;
        past_order[0] += 1;
        for refused in [order, past_order, [0xFF; 32]] {
            assert!(canonical_secret_scalar(&refused).is_none());
        }
    }
}
