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
//! The last input's blind balances the outputs' masks, and is not derived:
//! `shekyl-ct-balance`'s `PseudoOutBlinds::from_intent` takes the others
//! from here and balances them, as it does every spend's. Indexing by the
//! intent's input order, not the transaction's,
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
use crate::seeded_rng::SeededRng;

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

    /// Input `input`'s pseudo-out blind, `input` counted in the intent's
    /// input order. Every input's but the last is derived here; the last
    /// balances the outputs' masks, and `shekyl-ct-balance`'s
    /// `PseudoOutBlinds::from_intent`, the one reader, makes it.
    #[must_use]
    pub fn pseudo_out_blind(&self, input: usize) -> Zeroizing<Scalar> {
        expand_wide_scalar(
            &self.hkdf(),
            &make_info(LABEL_INTENT_PSEUDO_OUT_BLIND, index(input)),
        )
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
        assert_eq!(*a.pseudo_out_blind(1), *b.pseudo_out_blind(1));
        assert_ne!(*a.pseudo_out_blind(0), *a.pseudo_out_blind(1));
        assert_ne!(*a.pseudo_out_blind(0), *other.pseudo_out_blind(0));
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
