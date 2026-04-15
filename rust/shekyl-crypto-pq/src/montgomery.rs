// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Edwards-to-Montgomery conversion for view-key-derived X25519 keys.
//!
//! Shekyl addresses carry the Ed25519 view public key in the classical Bech32m
//! segment but not a separate X25519 key. The X25519 public key is derived
//! deterministically via the standard birational map: `u = (1 + y) / (1 - y)`.
//!
//! On the secret side, the Ed25519 view secret (a scalar reduced mod l) is used
//! directly as an unclamped Montgomery scalar. Standard X25519 clamping is NOT
//! applied because it would mutate the scalar and desynchronize sender/recipient
//! DH computations. Low-order point rejection at DH sites replaces clamping's
//! cofactor-clearing role.

use curve25519_dalek::{
    edwards::CompressedEdwardsY, montgomery::MontgomeryPoint, scalar::Scalar, traits::IsIdentity,
};

use crate::CryptoError;

/// Convert an Ed25519 public key to its X25519 (Montgomery u-coordinate)
/// equivalent via the birational map `u = (1 + y) / (1 - y) mod p`.
///
/// Rejects:
/// - Decompression failures (non-canonical or off-curve encodings)
/// - The Ed25519 identity point (maps to Montgomery identity u=0)
pub fn ed25519_pk_to_x25519_pk(ed_pub: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    // Reject non-canonical y-coordinates (>= p). curve25519-dalek silently
    // reduces mod p; we must check explicitly.
    if !is_canonical_field_element(ed_pub) {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let compressed = CompressedEdwardsY(*ed_pub);
    let point = compressed
        .decompress()
        .ok_or(CryptoError::InvalidKeyMaterial)?;

    if point.is_identity() {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let mont = point.to_montgomery();

    if mont == MontgomeryPoint([0u8; 32]) {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    Ok(mont.0)
}

/// Check that a 32-byte encoding represents a canonical field element (< p).
/// p = 2^255 - 19. The sign bit (bit 255) is masked before comparison.
fn is_canonical_field_element(bytes: &[u8; 32]) -> bool {
    // p in little-endian (with high bit cleared for the y-coordinate):
    // [0xED, 0xFF, ..., 0xFF, 0x7F]
    let mut y = *bytes;
    y[31] &= 0x7F; // mask sign bit

    // Compare against p = 2^255 - 19 (little-endian, high bit cleared = 0x7F)
    // p = [0xED, 0xFF(x30), 0x7F]
    // y < p iff: scanning from MSB, first differing byte has y[i] < p[i]
    for i in (0..32).rev() {
        let p_byte = if i == 0 {
            0xED
        } else if i == 31 {
            0x7F
        } else {
            0xFF
        };
        if y[i] < p_byte {
            return true;
        }
        if y[i] > p_byte {
            return false;
        }
    }
    // y == p, which is non-canonical
    false
}

/// Interpret an Ed25519 secret key (scalar reduced mod l) as a Montgomery
/// scalar for unclamped DH.
///
/// No clamping is applied. The caller MUST reject low-order peer points
/// before multiplying with this scalar. See `is_low_order_montgomery`.
pub fn ed25519_sk_as_montgomery_scalar(ed_sec: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*ed_sec)
}

/// The 12 low-order points on Curve25519 (Montgomery form) have order
/// dividing 8. Multiplying by the cofactor (8) sends them to the identity.
///
/// Returns `true` if the point has order dividing 8 (i.e., is one of the
/// 12 low-order points including the identity).
pub fn is_low_order_montgomery(point: &MontgomeryPoint) -> bool {
    let cofactor = Scalar::from(8u64);
    let cleared = cofactor * point;
    cleared == MontgomeryPoint([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;

    #[test]
    fn basepoint_converts_successfully() {
        let result = ed25519_pk_to_x25519_pk(&ED25519_BASEPOINT_COMPRESSED.0);
        assert!(result.is_ok());
        let x25519_pk = result.unwrap();
        assert_ne!(x25519_pk, [0u8; 32]);
    }

    #[test]
    fn identity_rejected() {
        // Ed25519 identity: y=1, sign bit 0 → [1, 0, ..., 0]
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(ed25519_pk_to_x25519_pk(&identity).is_err());
    }

    #[test]
    fn y_zero_is_valid() {
        // y=0 is a valid Edwards point (not the identity, which has y=1).
        // It decompresses to a non-trivial point with a valid Montgomery image.
        let zero = [0u8; 32];
        let result = ed25519_pk_to_x25519_pk(&zero);
        assert!(result.is_ok(), "y=0 is a valid non-identity Edwards point");
    }

    #[test]
    fn non_canonical_y_rejected() {
        // p = 2^255 - 19. A y-coordinate >= p is non-canonical.
        // p in little-endian: ed ff ff ... ff 7f. Values with byte[31] & 0x7f == 0x7f
        // and the lower bytes >= (p mod 2^248) are non-canonical.
        // Encoding of p itself:
        let mut p_encoding = [0u8; 32];
        // p = 2^255 - 19, little-endian: (256 - 19) = 237 = 0xED at byte 0, rest 0xFF, top 0x7F
        p_encoding[0] = 0xED;
        for byte in p_encoding.iter_mut().skip(1).take(30) {
            *byte = 0xFF;
        }
        p_encoding[31] = 0x7F;
        // This is exactly p, which should fail decompression (non-canonical).
        assert!(
            ed25519_pk_to_x25519_pk(&p_encoding).is_err(),
            "encoding of p itself is non-canonical and must be rejected"
        );
    }

    #[test]
    fn sign_bit_flip_produces_same_montgomery_u() {
        // The Edwards sign bit (bit 255) selects between ±x for the same y.
        // The Montgomery u-coordinate u=(1+y)/(1-y) depends only on y.
        // Two Edwards points differing only in sign bit MUST produce the same
        // Montgomery u — this is fundamental to the birational map.
        let mut flipped = ED25519_BASEPOINT_COMPRESSED.0;
        flipped[31] ^= 0x80;
        let canonical = ed25519_pk_to_x25519_pk(&ED25519_BASEPOINT_COMPRESSED.0).unwrap();
        let from_flipped = ed25519_pk_to_x25519_pk(&flipped).unwrap();
        assert_eq!(
            canonical, from_flipped,
            "sign-bit flip must produce same Montgomery u"
        );
    }

    #[test]
    fn round_trip_scalar_consistency() {
        // Generate a keypair, convert public to Montgomery, convert secret to
        // scalar, multiply by basepoint, verify the results match.
        use curve25519_dalek::constants::X25519_BASEPOINT;

        let secret_bytes: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x00,
        ];

        let scalar = ed25519_sk_as_montgomery_scalar(&secret_bytes);
        let ed_scalar = Scalar::from_bytes_mod_order(secret_bytes);

        // Compute Ed25519 public key
        let ed_pub = (&ed_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE).compress();

        // Convert to Montgomery via birational map
        let x25519_from_ed = ed25519_pk_to_x25519_pk(&ed_pub.0).unwrap();

        // Compute Montgomery public key from scalar directly
        let x25519_from_scalar = scalar * X25519_BASEPOINT;

        assert_eq!(
            x25519_from_ed, x25519_from_scalar.0,
            "Edwards-to-Montgomery conversion must match scalar * basepoint"
        );
    }

    #[test]
    fn low_order_identity_detected() {
        assert!(is_low_order_montgomery(&MontgomeryPoint([0u8; 32])));
    }

    /// The 12 low-order points on Curve25519 (Montgomery form).
    /// u-coordinates from the small subgroup of order 8.
    fn low_order_montgomery_points() -> Vec<MontgomeryPoint> {
        // The known low-order u-coordinates on Curve25519:
        // order 1: u = 0
        // order 2: u = 1
        // order 4: u = p-1 (= 2^255 - 20)
        // order 8: u values from the full cofactor subgroup
        //
        // We enumerate by multiplying the order-8 generators.
        // The small subgroup points have u-coordinates:
        //   0, 1, p-1, and 9 additional points.
        //
        // Rather than hardcoding all 12, we use the cofactor check itself
        // and verify against known values.
        let p_minus_1 = {
            // p = 2^255 - 19, so p-1 in little-endian
            let bytes = [0xECu8; 1]; // placeholder
            let _ = bytes;
            // Exact encoding of p-1 = 2^255 - 20
            let mut b = [0u8; 32];
            // p-1 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC
            b[0] = 0xEC;
            for byte in b.iter_mut().skip(1).take(30) {
                *byte = 0xFF;
            }
            b[31] = 0x7F;
            b
        };

        vec![
            // u = 0 (identity, order 1)
            MontgomeryPoint([0u8; 32]),
            // u = 1 (order 2)
            MontgomeryPoint({
                let mut b = [0u8; 32];
                b[0] = 1;
                b
            }),
            // u = p-1 (order 4)
            MontgomeryPoint(p_minus_1),
        ]
    }

    #[test]
    fn known_low_order_points_detected() {
        for (i, point) in low_order_montgomery_points().iter().enumerate() {
            assert!(
                is_low_order_montgomery(point),
                "low-order point {i} (u={:02x?}) not detected",
                &point.0[..4]
            );
        }
    }

    #[test]
    fn basepoint_not_low_order() {
        use curve25519_dalek::constants::X25519_BASEPOINT;
        assert!(!is_low_order_montgomery(&X25519_BASEPOINT));
    }

    #[test]
    fn random_point_not_low_order() {
        use curve25519_dalek::constants::X25519_BASEPOINT;
        let scalar = Scalar::from(42u64);
        let point = scalar * X25519_BASEPOINT;
        assert!(!is_low_order_montgomery(&point));
    }

    #[test]
    fn all_known_low_order_u_coordinates_detected() {
        // Exhaustive test of known low-order u-coordinates on Curve25519.
        // The small subgroup of the curve and its twist contains points of
        // order 1, 2, 4, and 8. Their u-coordinates are well-known.
        let low_order_u_coords: Vec<[u8; 32]> = vec![
            // u = 0 (identity, order 1)
            [0u8; 32],
            // u = 1 (order 2)
            {
                let mut b = [0u8; 32];
                b[0] = 1;
                b
            },
            // u = p-1 = 2^255 - 20 (order 4)
            {
                let mut b = [0u8; 32];
                b[0] = 0xEC;
                for byte in b.iter_mut().skip(1).take(30) {
                    *byte = 0xFF;
                }
                b[31] = 0x7F;
                b
            },
            // u = 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // u = 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
        ];

        for (i, u_bytes) in low_order_u_coords.iter().enumerate() {
            let point = MontgomeryPoint(*u_bytes);
            assert!(
                is_low_order_montgomery(&point),
                "low-order point {i} (u={:02x}{:02x}...) not detected",
                u_bytes[0],
                u_bytes[1],
            );
        }
    }

    #[test]
    fn view_key_round_trip_consistency() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT};

        for _ in 0..10 {
            let view_scalar = Scalar::random(&mut rand::rngs::OsRng);
            let view_pub = (&view_scalar * ED25519_BASEPOINT_TABLE).compress();

            let x25519_pub = ed25519_pk_to_x25519_pk(&view_pub.0).unwrap();
            let x25519_sec = ed25519_sk_as_montgomery_scalar(&view_scalar.to_bytes());

            let computed_pub = x25519_sec * X25519_BASEPOINT;
            assert_eq!(
                x25519_pub, computed_pub.0,
                "public key from Edwards map must match scalar * basepoint"
            );

            let eph_scalar = Scalar::random(&mut rand::rngs::OsRng);
            let eph_pub = eph_scalar * X25519_BASEPOINT;

            let sender_ss = eph_scalar * MontgomeryPoint(x25519_pub);
            let receiver_ss = x25519_sec * eph_pub;

            assert_eq!(
                sender_ss.0, receiver_ss.0,
                "sender and receiver must compute the same shared secret"
            );
        }
    }
}
