// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a spend key holds an output, and the key image when it does.
//!
//! One ML-KEM decapsulation, the view tag, and `O = ho·G + B + y·T`. The
//! image is `I = (ho + b)·Hp(O)`. The amount, the commitment, the ML-DSA
//! key and the bytes of `b`'s sum with `ho` belong to the scan and to
//! signing ([`crate::output::compute_output_key_image`]), not to this
//! answer.

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use zeroize::Zeroizing;

use crate::derivation::derive_output_opening;
use crate::kem::{combine_shared_secrets, MlKemDecapsKey};
use crate::output::{
    image_from_spend_scalar, ml_kem_decap_prefilter_with_dk, output_key_holds, prime_order_point,
    x25519_shared_secret, Prefilter,
};
use crate::CryptoError;

/// Whether this spend key holds the output, and the key image when it does.
///
/// [`NotHeld`](Self::NotHeld) is a view-tag miss or an output-key miss: the
/// ciphertext opened far enough to decide, and the output is not this key's.
/// A malformed ciphertext, a low-order point, or a decapsulation failure is
/// `Err` from [`held_key_image`]: the output did not open, which is a
/// different fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldKeyImage {
    /// This spend key holds the output. The image is `I = (ho + b)·Hp(O)`.
    Held(crate::key_image::KeyImage),
    /// The view tag missed, or `O` is not `ho·G + B + y·T` for this spend key.
    NotHeld,
}

/// The spend key asking whether it holds an output.
///
/// The public and the secret are one key. A secret that is not `b` for
/// `spend_public` is [`CryptoError::InvalidKeyMaterial`] once the output
/// key has matched, never a key image.
#[derive(Clone, Copy)]
pub struct HoldingSpendKey<'a> {
    /// X25519 view secret.
    pub x25519_sk: &'a [u8; 32],
    /// ML-KEM-768 decapsulation key (`ML_KEM_768_DK_LEN` bytes).
    pub ml_kem_dk: &'a [u8],
    /// Edwards spend public key `B`.
    pub spend_public: &'a [u8; 32],
    /// Edwards spend secret `b`.
    pub spend_secret: &'a [u8; 32],
}

/// The on-chain fields a key image is opened from.
///
/// Holding is the view tag and `O = ho·G + B + y·T`. The image is
/// `(ho + b)·Hp(O)`. The amount, the commitment and the ML-DSA key are not
/// among these fields.
#[derive(Clone, Copy)]
pub struct KeyImageOutput<'a> {
    /// Ephemeral X25519 public key.
    pub kem_ct_x25519: &'a [u8; 32],
    /// ML-KEM-768 ciphertext.
    pub kem_ct_ml_kem: &'a [u8],
    /// Compressed output key `O`.
    pub output_key: &'a [u8; 32],
    /// On-chain view tag.
    pub view_tag: u8,
    /// Output index in its transaction. A coinbase's one output is 0.
    pub output_index: u64,
}

/// The key image of an output `holder` holds, or why it does not.
///
/// One ML-KEM decapsulation. A view-tag miss or an output-key miss is
/// [`HeldKeyImage::NotHeld`]. A malformed ciphertext, a low-order ephemeral
/// point, or a decapsulation failure is `Err`. The spend scalar `ho + b`
/// is used for the multiplication and is not encoded.
///
/// # Errors
///
/// [`CryptoError::DecapsulationFailed`] when the ML-KEM ciphertext does not
/// open. [`CryptoError::LowOrderPoint`] when the ephemeral X25519 point is
/// low order. [`CryptoError::InvalidKeyMaterial`] when `spend_secret` is
/// not `b` for `spend_public`, or when `Hp(O)` is not a prime-order point.
pub fn held_key_image(
    holder: &HoldingSpendKey<'_>,
    output: &KeyImageOutput<'_>,
) -> Result<HeldKeyImage, CryptoError> {
    let decaps_key = MlKemDecapsKey::from_bytes(holder.ml_kem_dk)?;
    let ml_shared_secret = match ml_kem_decap_prefilter_with_dk(
        decaps_key.as_decaps_key(),
        output.kem_ct_ml_kem,
        output.view_tag,
        output.output_index,
    )? {
        Prefilter::NotForThisKey => return Ok(HeldKeyImage::NotHeld),
        Prefilter::Matched(shared_secret) => shared_secret,
    };

    let view_shared = x25519_shared_secret(holder.x25519_sk, output.kem_ct_x25519)?;
    let combined = combine_shared_secrets(&view_shared.0, &*ml_shared_secret)?;
    let opening = derive_output_opening(&combined.0, output.output_index);
    if !output_key_holds(
        &opening.ho,
        &opening.y,
        holder.spend_public,
        output.output_key,
    )? {
        return Ok(HeldKeyImage::NotHeld);
    }

    // The equation used `B`. The image uses `b`. They are one key.
    let spend_secret: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(*holder.spend_secret))
            .ok_or(CryptoError::InvalidKeyMaterial)?,
    );
    if EdwardsPoint::mul_base(&spend_secret).compress().to_bytes() != *holder.spend_public {
        return Err(CryptoError::InvalidKeyMaterial);
    }

    let ho: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_canonical_bytes(opening.ho))
            .expect("ho from wide_reduce is always canonical"),
    );
    let hp_of_output = prime_order_point(shekyl_curve_generators::biased_hash_to_point(
        *output.output_key,
    ))?;
    // `x = ho + b` stays a scalar. Its bytes are the signing secret, and
    // this function does not return them.
    let spend_scalar: Zeroizing<Scalar> = Zeroizing::new(*ho + *spend_secret);
    Ok(HeldKeyImage::Held(image_from_spend_scalar(
        &spend_scalar,
        &hp_of_output,
    )))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
    use zeroize::Zeroizing;

    use super::{held_key_image, HeldKeyImage, HoldingSpendKey, KeyImageOutput};
    use crate::kem::{HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation};
    use crate::output::{
        compute_output_key_image, construct_output, ml_kem_ss_wiped_on_last_prefilter_reject,
        recover_combined_ss, reset_ml_kem_ss_wipe_probe, OutputData, VIEW_TAG_MISS_SAMPLES,
    };
    use crate::tx_key::TxKey;
    use crate::CryptoError;

    /// The amount a fixture output carries. The image does not depend on it.
    const FIXTURE_AMOUNT: u64 = 500;

    /// Output index of every fixture here. A coinbase's one output is the same index.
    const FIXTURE_OUTPUT: u64 = 0;

    /// One output addressed to a fresh spend key, and the key that holds it.
    struct HeldFixture {
        kem_sk: HybridKemSecretKey,
        spend_public: [u8; 32],
        spend_secret: Zeroizing<[u8; 32]>,
        output: OutputData,
    }

    impl HeldFixture {
        fn generate() -> Self {
            let kem = HybridX25519MlKem;
            let (recipient_pk, recipient_sk) = kem.keypair_generate().unwrap();
            let spend_scalar = Scalar::random(&mut rand::rngs::OsRng);
            let spend_public = (G * spend_scalar).compress().to_bytes();
            let output = construct_output(
                &TxKey::random().expect("the OS draws a key"),
                &recipient_pk.x25519,
                &recipient_pk.ml_kem,
                &spend_public,
                FIXTURE_AMOUNT,
                FIXTURE_OUTPUT,
            )
            .unwrap();
            Self {
                kem_sk: recipient_sk,
                spend_public,
                spend_secret: Zeroizing::new(spend_scalar.to_bytes()),
                output,
            }
        }

        fn holder(&self) -> HoldingSpendKey<'_> {
            HoldingSpendKey {
                x25519_sk: &self.kem_sk.x25519,
                ml_kem_dk: &self.kem_sk.ml_kem,
                spend_public: &self.spend_public,
                spend_secret: &self.spend_secret,
            }
        }

        fn output(&self) -> KeyImageOutput<'_> {
            KeyImageOutput {
                kem_ct_x25519: &self.output.kem_ciphertext_x25519,
                kem_ct_ml_kem: &self.output.kem_ciphertext_ml_kem,
                output_key: &self.output.output_key,
                view_tag: self.output.view_tag_prefilter,
                output_index: FIXTURE_OUTPUT,
            }
        }
    }

    #[test]
    fn held_key_image_matches_the_signing_paths_image() {
        let fixture = HeldFixture::generate();
        let held = held_key_image(&fixture.holder(), &fixture.output()).unwrap();
        let combined = recover_combined_ss(
            &fixture.kem_sk.x25519,
            &fixture.kem_sk.ml_kem,
            &fixture.output.kem_ciphertext_x25519,
            &fixture.output.kem_ciphertext_ml_kem,
        )
        .unwrap();
        let hp_of_output = shekyl_curve_generators::biased_hash_to_point(fixture.output.output_key)
            .compress()
            .to_bytes();
        let image = compute_output_key_image(
            &combined.0,
            FIXTURE_OUTPUT,
            &fixture.spend_secret,
            &hp_of_output,
        )
        .unwrap()
        .key_image;
        assert_eq!(held, HeldKeyImage::Held(image));
    }

    #[test]
    fn a_spend_key_that_does_not_hold_the_output_is_not_held() {
        let fixture = HeldFixture::generate();
        let other = Scalar::random(&mut rand::rngs::OsRng);
        let other_public = (G * other).compress().to_bytes();
        let other_secret = Zeroizing::new(other.to_bytes());
        let holder = HoldingSpendKey {
            spend_public: &other_public,
            spend_secret: &other_secret,
            ..fixture.holder()
        };
        assert_eq!(
            held_key_image(&holder, &fixture.output()).unwrap(),
            HeldKeyImage::NotHeld
        );
    }

    #[test]
    fn a_secret_that_is_not_its_spend_public_does_not_open_an_image() {
        let fixture = HeldFixture::generate();
        let other = Zeroizing::new(Scalar::random(&mut rand::rngs::OsRng).to_bytes());
        let holder = HoldingSpendKey {
            spend_secret: &other,
            ..fixture.holder()
        };
        assert!(matches!(
            held_key_image(&holder, &fixture.output()),
            Err(CryptoError::InvalidKeyMaterial)
        ));
    }

    #[test]
    fn a_view_tag_miss_is_not_held_and_wipes_the_shared_secret() {
        let fixture = HeldFixture::generate();
        let kem = HybridX25519MlKem;
        let mut saw_miss = false;
        for _ in 0..VIEW_TAG_MISS_SAMPLES {
            let (_, wrong_sk) = kem.keypair_generate().unwrap();
            reset_ml_kem_ss_wipe_probe();
            let holder = HoldingSpendKey {
                x25519_sk: &wrong_sk.x25519,
                ml_kem_dk: &wrong_sk.ml_kem,
                ..fixture.holder()
            };
            // A tag collision still returns NotHeld, from the output-key
            // check, and that path does not wipe. Only a wiped miss is the
            // pre-filter this test is about.
            if held_key_image(&holder, &fixture.output()).unwrap() == HeldKeyImage::NotHeld
                && ml_kem_ss_wiped_on_last_prefilter_reject()
            {
                saw_miss = true;
                break;
            }
        }
        assert!(
            saw_miss,
            "a wrong KEM key hits the view-tag miss within {VIEW_TAG_MISS_SAMPLES} samples"
        );
        assert!(
            ml_kem_ss_wiped_on_last_prefilter_reject(),
            "the shared secret is wiped on a view-tag miss"
        );
    }

    #[test]
    fn a_ciphertext_that_does_not_open_is_not_a_miss() {
        let fixture = HeldFixture::generate();
        let mut output = fixture.output();
        let short = [0u8; 1];
        output.kem_ct_ml_kem = &short;
        assert!(matches!(
            held_key_image(&fixture.holder(), &output),
            Err(CryptoError::DecapsulationFailed(_))
        ));

        let mut low_order = fixture.output();
        // The Montgomery identity is low order, so the X25519 half refuses it.
        let identity = [0u8; 32];
        low_order.kem_ct_x25519 = &identity;
        assert!(matches!(
            held_key_image(&fixture.holder(), &low_order),
            Err(CryptoError::LowOrderPoint)
        ));
    }
}
