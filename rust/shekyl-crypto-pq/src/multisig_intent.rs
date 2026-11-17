// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a multisig spend takes from its intent instead of the OS
//! (`PQC_MULTISIG.md` §9.5, R-7, R-14).
//!
//! A solo spend draws its transaction key, its pseudo-out blinds and each
//! input's rerandomization at random. A group's members build one
//! transaction apart, so each of them derives those values from the
//! intent's `kem_randomness_seed`, under one HKDF label per value:
//!
//! | Value | Label | Indexed by |
//! | --- | --- | --- |
//! | the transaction key (and so every output; [`crate::TxKey::from_intent_seed`]) | [`LABEL_INTENT_TX_KEY`] | — |
//! | each input's pseudo-out blind but the last | [`LABEL_INTENT_PSEUDO_OUT_BLIND`] | the intent's input order |
//! | each input's rerandomization seed | [`LABEL_INTENT_RERANDOMIZE`] | the intent's input order |
//! | the seed's replay fingerprint | [`LABEL_INTENT_SEED_FINGERPRINT`] | — |
//!
//! The last input's blind balances the outputs' masks
//! ([`crate::output::balancing_pseudo_out_blind`], the solo spend's own
//! balancer). Indexing by the intent's input order, not the transaction's,
//! lets a member derive every value before it knows the key images that
//! order the transaction's inputs.
//!
//! The seed is secret to the group: the intent travels only inside sealed
//! ceremony files, so no outsider can derive these values. A member keeps
//! no seed after its ceremony: the set it refuses a replayed intent from
//! holds each seed's fingerprint ([`IntentSeed::fingerprint`]), a one-way
//! value under its own label, never the seed. The range proof
//! and the membership proof's own blinds are not here: the proposer draws
//! them, and every member verifies the proofs instead of rebuilding them.

use curve25519_dalek::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::derivation::{expand_32_into, expand_wide_scalar, make_info};
use crate::output::balancing_pseudo_out_blind;
use crate::seeded_rng::SeededRng;
use crate::CryptoError;

/// HKDF info of the transaction key.
pub const LABEL_INTENT_TX_KEY: &[u8] = b"shekyl/multisig-intent-tx-key-v1";
/// HKDF info prefix of each input's pseudo-out blind.
pub const LABEL_INTENT_PSEUDO_OUT_BLIND: &[u8] = b"shekyl/multisig-intent-pseudo-out-blind-v1";
/// HKDF info prefix of each input's rerandomization seed.
pub const LABEL_INTENT_RERANDOMIZE: &[u8] = b"shekyl/multisig-intent-rerandomize-v1";
/// HKDF info of the seed's replay fingerprint.
pub const LABEL_INTENT_SEED_FINGERPRINT: &[u8] = b"shekyl/multisig-intent-seed-fingerprint-v1";

/// The length of an intent's seed, as its canonical encoding carries it.
pub const INTENT_SEED_LEN: usize = 32;

/// The length of an input's rerandomization seed.
pub const RERANDOMIZATION_SEED_LEN: usize = 32;

/// One input's rerandomization seed: the root of the stream that draws the
/// input's rerandomization blinds (`r_o`, `r_i`, `r_r_i`; never a signing
/// nonce). Made from an intent's seed, per input in the intent's input
/// order ([`IntentSeed::rerandomization_seed`]), so every member derives
/// the same one and two inputs of one intent never share one: inputs that
/// shared blinds would link to each other. Wiped on drop, never printed,
/// never cloned; its one reader is [`Self::rng`].
pub struct RerandomizationSeed(Zeroizing<[u8; RERANDOMIZATION_SEED_LEN]>);

impl RerandomizationSeed {
    /// The ChaCha20 stream over this seed, which draws the input's blinds
    /// (`shekyl_fcmp::frost_sal::SalSigningParams::new`).
    #[must_use]
    pub fn rng(&self) -> SeededRng {
        SeededRng::from_seed(&self.0)
    }

    /// The seed `bytes`, so a fixture can pin an input's rerandomization.
    /// Only under the TEST_ONLY `seeded-rng` feature, which no build that
    /// ships enables (`CF-R9`).
    #[cfg(feature = "seeded-rng")]
    #[must_use]
    pub fn seeded(bytes: [u8; RERANDOMIZATION_SEED_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for RerandomizationSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RerandomizationSeed(..)")
    }
}

/// An intent's `kem_randomness_seed`, held as the root of every value the
/// spend derives from it. Wiped on drop; never printed; cloned only as an
/// intent is; no accessor returns its bytes ([`Self::encode_into`] writes
/// them into the intent's canonical encoding, which travels sealed).
#[derive(Clone)]
pub struct IntentSeed(Zeroizing<[u8; INTENT_SEED_LEN]>);

/// The one-way fingerprint of an [`IntentSeed`]: what a member's replay
/// set holds in place of the seed. Public: it opens nothing the seed does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IntentSeedFingerprint([u8; 32]);

impl IntentSeedFingerprint {
    /// The fingerprint's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for IntentSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IntentSeed(..)")
    }
}

impl IntentSeed {
    /// The seed an intent's canonical encoding carries.
    #[must_use]
    pub fn new(seed: &[u8; INTENT_SEED_LEN]) -> Self {
        Self(Zeroizing::new(*seed))
    }

    /// Append the seed's bytes to `out`, an intent's canonical encoding.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.as_ref());
    }

    /// The seed's replay fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> IntentSeedFingerprint {
        let mut fingerprint = [0u8; 32];
        self.hkdf()
            .expand(LABEL_INTENT_SEED_FINGERPRINT, &mut fingerprint)
            .expect("32 bytes is a valid HKDF-SHA-512 output length");
        IntentSeedFingerprint(fingerprint)
    }

    fn hkdf(&self) -> Hkdf<Sha512> {
        Hkdf::<Sha512>::new(None, self.0.as_ref())
    }

    /// The spend's transaction key's scalar, for
    /// [`crate::TxKey::from_intent_seed`], the one place it becomes a key.
    pub(crate) fn tx_key_scalar(&self) -> Zeroizing<Scalar> {
        expand_wide_scalar(&self.hkdf(), LABEL_INTENT_TX_KEY)
    }

    /// Input `input`'s rerandomization seed, `input` counted in the
    /// intent's input order.
    #[must_use]
    pub fn rerandomization_seed(&self, input: usize) -> RerandomizationSeed {
        let mut seed = Zeroizing::new([0u8; RERANDOMIZATION_SEED_LEN]);
        expand_32_into(
            &self.hkdf(),
            LABEL_INTENT_RERANDOMIZE,
            index(input),
            &mut seed,
        );
        RerandomizationSeed(seed)
    }

    /// Every input's pseudo-out blind, in the intent's input order: each
    /// derived but the last, which balances `output_masks`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidInput`] for a spend with no input;
    /// [`CryptoError::InvalidKeyMaterial`] for a mask that is not a
    /// canonical scalar.
    pub fn pseudo_out_blinds(
        &self,
        inputs: usize,
        output_masks: &[[u8; 32]],
    ) -> Result<Vec<Zeroizing<[u8; 32]>>, CryptoError> {
        let derived_count = inputs
            .checked_sub(1)
            .ok_or_else(|| CryptoError::InvalidInput("a spend has at least one input".into()))?;
        let hk = self.hkdf();
        let mut blinds: Vec<Zeroizing<[u8; 32]>> = (0..derived_count)
            .map(|input| {
                let info = make_info(LABEL_INTENT_PSEUDO_OUT_BLIND, index(input));
                Zeroizing::new(expand_wide_scalar(&hk, &info).to_bytes())
            })
            .collect();
        blinds.push(balancing_pseudo_out_blind(&blinds, output_masks)?);
        Ok(blinds)
    }
}

/// An input position as the HKDF info's index.
fn index(input: usize) -> u64 {
    u64::try_from(input).expect("a usize fits in a u64 on every target Shekyl builds for")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxKey;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

    fn mask(n: u64) -> [u8; 32] {
        Scalar::from(n).to_bytes()
    }

    /// Two members holding the same seed derive the same values, and each
    /// value differs from the others and from another seed's.
    #[test]
    fn members_with_one_seed_derive_one_spend() {
        let a = IntentSeed::new(&[0x51; 32]);
        let b = IntentSeed::new(&[0x51; 32]);
        let other = IntentSeed::new(&[0x52; 32]);
        let key = |seed: &IntentSeed| TxKey::from_intent_seed(seed).public_bytes();
        assert_eq!(key(&a), key(&b));
        assert_ne!(key(&a), key(&other));
        assert_eq!(*a.rerandomization_seed(1).0, *b.rerandomization_seed(1).0);
        assert_ne!(*a.rerandomization_seed(0).0, *a.rerandomization_seed(1).0);
        let masks = [mask(7), mask(11)];
        let blinds_a = a.pseudo_out_blinds(3, &masks).unwrap();
        let blinds_b = b.pseudo_out_blinds(3, &masks).unwrap();
        assert_eq!(blinds_a.len(), 3);
        assert!(blinds_a.iter().zip(&blinds_b).all(|(x, y)| **x == **y));
        assert_ne!(*blinds_a[0], *blinds_a[1]);
    }

    /// The blinds sum to the outputs' masks: the pseudo outputs balance the
    /// commitments. A single input takes the whole balance.
    #[test]
    fn the_blinds_balance_the_outputs_masks() {
        let seed = IntentSeed::new(&[0x61; 32]);
        let masks = [mask(5), mask(9), mask(13)];
        let mask_sum = Scalar::from(27u64);
        for inputs in 1..=4 {
            let blinds = seed.pseudo_out_blinds(inputs, &masks).unwrap();
            let sum: Scalar = blinds
                .iter()
                .map(|b| Scalar::from_canonical_bytes(**b).unwrap())
                .sum();
            assert_eq!(sum, mask_sum);
        }
        assert!(seed.pseudo_out_blinds(0, &masks).is_err());
        assert!(seed.pseudo_out_blinds(2, &[[0xFF; 32]]).is_err());
    }

    /// A seed's fingerprint is one-way and its own: it is not the seed,
    /// nor any value the seed derives, and another seed's differs.
    #[test]
    fn the_fingerprint_is_none_of_the_seeds_values() {
        let bytes = [0x81; INTENT_SEED_LEN];
        let seed = IntentSeed::new(&bytes);
        let fingerprint = *seed.fingerprint().as_bytes();
        assert_eq!(
            fingerprint,
            *IntentSeed::new(&bytes).fingerprint().as_bytes()
        );
        assert_ne!(fingerprint, bytes);
        assert_ne!(fingerprint, *TxKey::from_intent_seed(&seed).ikm());
        assert_ne!(fingerprint, *seed.rerandomization_seed(0).0);
        assert_ne!(
            seed.fingerprint(),
            IntentSeed::new(&[0x82; INTENT_SEED_LEN]).fingerprint()
        );
    }

    /// The seed and an input's rerandomization seed print as nothing, and
    /// the seed's encoding is its bytes.
    #[test]
    fn the_seed_never_prints() {
        let seed = IntentSeed::new(&[0xAB; INTENT_SEED_LEN]);
        let printed = format!("{seed:?}");
        assert!(
            !printed.contains("ab") && !printed.contains("171"),
            "{printed}"
        );
        assert_eq!(
            format!("{:?}", seed.rerandomization_seed(0)),
            "RerandomizationSeed(..)"
        );
        let mut encoded = Vec::new();
        seed.clone().encode_into(&mut encoded);
        assert_eq!(encoded, [0xAB; INTENT_SEED_LEN]);
    }

    /// An input's stream is ChaCha20 over its rerandomization seed.
    #[test]
    fn an_inputs_stream_is_its_seeds() {
        use rand::RngCore as _;
        let seed = IntentSeed::new(&[0x91; 32]).rerandomization_seed(2);
        let [mut a, mut b] = [seed.rng(), SeededRng::from_seed(&seed.0)];
        assert_eq!(a.next_u64(), b.next_u64());
    }

    /// The key from a seed is the derived scalar, canonical, and its
    /// public half is `r·G`.
    #[test]
    fn the_tx_key_publishes_its_point() {
        let seed = IntentSeed::new(&[0x71; 32]);
        let key = TxKey::from_intent_seed(&seed);
        let r = *seed.tx_key_scalar();
        assert_eq!(*key.ikm(), r.to_bytes());
        assert_eq!(
            (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
            key.public_bytes()
        );
    }
}
