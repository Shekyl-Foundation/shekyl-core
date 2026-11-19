// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A spend's pseudo-out blinds, balanced by construction: [`PseudoOutBlinds`].
//!
//! Each input's pseudo output is `C̃ = a·G + amount·H`. The balance
//! equation (this crate's [`verify_ct_balance`](crate::verify_ct_balance))
//! holds only when the inputs' blinds `a` sum to the outputs' commitment
//! masks (the fee and every cleartext term ride at mask zero). So every
//! input's blind but the last is free, and the last is the outputs' masks
//! less the others. That arithmetic is done here, once, for every spend:
//! no signer takes a generator for its blinds, and no value of the type
//! fails to balance.
//!
//! The free blinds come from one of three places, one constructor each:
//!
//! | Constructor | The free blinds | Who |
//! | --- | --- | --- |
//! | [`PseudoOutBlinds::random`] | the OS | a solo spend |
//! | [`PseudoOutBlinds::from_intent`] | the intent's seed, in the intent's input order (`PQC_MULTISIG.md` §9.5) | a group's spend: every member derives the same blinds |
//! | [`PseudoOutBlinds::seeded`] | a ChaCha20 stream over a caller's seed, only under the TEST_ONLY `seeded-rng` feature | the chain forge's reproducible chains (`CHAIN_FORGE.md` §5.2, S2) |
//!
//! A drawn blind is `Scalar::random` over the generator, one per input but
//! the last, in input order: the seeded stream reproduces the forge's
//! byte for byte.

use std::fmt;
use std::num::NonZeroUsize;

use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use shekyl_crypto_pq::multisig_intent::IntentSeed;
use shekyl_curve_primitives::Commitment;
use zeroize::Zeroizing;

/// Every input's pseudo-out blind, in input order, the last balancing the
/// outputs' commitment masks. Made only by this module's constructors, so
/// the blinds always sum to the masks of the outputs they were built for.
/// It wipes on drop and prints its count only.
pub struct PseudoOutBlinds(Zeroizing<Vec<Scalar>>);

impl PseudoOutBlinds {
    /// A solo spend's blinds: each but the last drawn from the OS, the last
    /// balancing `outputs`, the outputs' openings.
    #[must_use]
    pub fn random(inputs: NonZeroUsize, outputs: &[Commitment]) -> Self {
        Self::drawn(&mut OsRng, inputs, outputs)
    }

    /// A group's blinds: input `j`'s, for every input but the last, derived
    /// from the intent's seed under its index in the intent's input order
    /// ([`IntentSeed::pseudo_out_blind`]), the last balancing `outputs`.
    /// Every member holding the intent derives the same blinds.
    #[must_use]
    pub fn from_intent(seed: &IntentSeed, inputs: NonZeroUsize, outputs: &[Commitment]) -> Self {
        Self::balancing(
            inputs,
            (0..inputs.get() - 1).map(|input| seed.pseudo_out_blind(input)),
            outputs,
        )
    }

    /// Blinds drawn from a ChaCha20 stream over `seed`, for reproducible
    /// chains: the same seed gives the same blinds. Only under the TEST_ONLY
    /// `seeded-rng` feature, which no build that ships enables (`CF-R9`).
    #[cfg(feature = "seeded-rng")]
    #[must_use]
    pub fn seeded(seed: &[u8; 32], inputs: NonZeroUsize, outputs: &[Commitment]) -> Self {
        use rand_chacha::rand_core::SeedableRng;
        Self::drawn(
            &mut rand_chacha::ChaCha20Rng::from_seed(*seed),
            inputs,
            outputs,
        )
    }

    /// Every blind but the last drawn from `rng`, in input order.
    fn drawn<R: RngCore + CryptoRng>(
        rng: &mut R,
        inputs: NonZeroUsize,
        outputs: &[Commitment],
    ) -> Self {
        Self::balancing(
            inputs,
            (1..inputs.get()).map(|_| Zeroizing::new(Scalar::random(rng))),
            outputs,
        )
    }

    /// `free` (every input's blind but the last), then the blind that
    /// balances `outputs`: their masks less every free blind.
    ///
    /// The set is allocated once, at its size: a vector that grew would
    /// free its earlier buffers, blinds in them, without wiping them, and
    /// `Zeroizing` wipes only the buffer it holds when it drops.
    fn balancing(
        inputs: NonZeroUsize,
        free: impl Iterator<Item = Zeroizing<Scalar>>,
        outputs: &[Commitment],
    ) -> Self {
        let mut last = Zeroizing::new(Scalar::ZERO);
        for output in outputs {
            *last += output.mask;
        }
        let mut blinds = Zeroizing::new(Vec::with_capacity(inputs.get()));
        for blind in free {
            *last -= &*blind;
            blinds.push(*blind);
        }
        blinds.push(*last);
        debug_assert_eq!(blinds.len(), inputs.get(), "one blind per input");
        Self(blinds)
    }

    /// The number of blinds, one per input.
    #[must_use]
    pub fn len(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.0.len()).expect("a balanced set holds the last input's blind")
    }

    /// Each input's blind as the 32 bytes the prover takes, in input order.
    #[must_use]
    pub fn into_bytes(self) -> Vec<Zeroizing<[u8; 32]>> {
        self.0
            .iter()
            .map(|blind| Zeroizing::new(blind.to_bytes()))
            .collect()
    }
}

impl fmt::Debug for PseudoOutBlinds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PseudoOutBlinds({} inputs)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT_COUNTS: [usize; 4] = [1, 2, 3, 8];

    fn inputs(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("a test count is not zero")
    }

    fn outputs(masks: &[u64]) -> Vec<Commitment> {
        masks
            .iter()
            .map(|&mask| Commitment::new(Scalar::from(mask), 0))
            .collect()
    }

    fn sum(blinds: PseudoOutBlinds) -> Scalar {
        blinds
            .into_bytes()
            .iter()
            .map(|bytes| Scalar::from_canonical_bytes(**bytes).expect("a blind is canonical"))
            .sum()
    }

    /// Every constructor's blinds sum to the outputs' masks, for any input
    /// count: one input takes the whole balance.
    #[test]
    fn every_set_of_blinds_balances_the_outputs_masks() {
        let outputs = outputs(&[5, 9, 13]);
        let masks = Scalar::from(27u64);
        let seed = IntentSeed::new(&[0x61; 32]);
        for n in INPUT_COUNTS {
            let random = PseudoOutBlinds::random(inputs(n), &outputs);
            assert_eq!(random.len(), inputs(n));
            assert_eq!(sum(random), masks, "random, {n} input(s)");
            assert_eq!(
                sum(PseudoOutBlinds::from_intent(&seed, inputs(n), &outputs)),
                masks,
                "from the intent, {n} input(s)"
            );
        }
    }

    /// A group's blinds are the intent seed's derivations, in the intent's
    /// input order, and only the seed decides them: two members with one
    /// seed derive one set, another seed another.
    #[test]
    fn a_groups_blinds_are_its_intents() {
        let outputs = outputs(&[7, 11]);
        let seed = IntentSeed::new(&[0x51; 32]);
        let blinds = PseudoOutBlinds::from_intent(&seed, inputs(3), &outputs).into_bytes();
        for (input, blind) in blinds.iter().take(2).enumerate() {
            assert_eq!(**blind, seed.pseudo_out_blind(input).to_bytes());
        }
        assert_ne!(*blinds[0], *blinds[1]);
        let again =
            PseudoOutBlinds::from_intent(&IntentSeed::new(&[0x51; 32]), inputs(3), &outputs)
                .into_bytes();
        assert!(blinds.iter().zip(&again).all(|(a, b)| **a == **b));
        let other =
            PseudoOutBlinds::from_intent(&IntentSeed::new(&[0x52; 32]), inputs(3), &outputs)
                .into_bytes();
        assert_ne!(*blinds[0], *other[0]);
    }

    /// The OS draws a fresh set each time.
    #[test]
    fn a_solo_spends_blinds_are_fresh() {
        let outputs = outputs(&[3]);
        let [a, b] = [(); 2].map(|()| PseudoOutBlinds::random(inputs(2), &outputs).into_bytes());
        assert_ne!(*a[0], *b[0]);
    }

    /// The set is allocated once, at its size, so no grown-out buffer of
    /// blinds is freed unwiped: at three inputs a vector that grew would
    /// hold four slots.
    #[test]
    fn a_set_of_blinds_is_allocated_once() {
        let outputs = outputs(&[2]);
        let seed = IntentSeed::new(&[0x71; 32]);
        for blinds in [
            PseudoOutBlinds::random(inputs(3), &outputs),
            PseudoOutBlinds::from_intent(&seed, inputs(3), &outputs),
        ] {
            assert_eq!(blinds.0.capacity(), 3);
        }
    }

    /// The blinds print their count and nothing of themselves.
    #[test]
    fn blinds_never_print() {
        let blinds = PseudoOutBlinds::random(inputs(3), &outputs(&[1]));
        assert_eq!(format!("{blinds:?}"), "PseudoOutBlinds(3 inputs)");
    }

    /// A seeded set is the seed's: the same seed gives the same blinds, and
    /// they are `Scalar::random` over one ChaCha20 stream, one per input
    /// but the last, in input order (the forge's S2 stream).
    #[cfg(feature = "seeded-rng")]
    #[test]
    fn a_seeded_set_is_its_streams() {
        use rand_chacha::rand_core::SeedableRng;
        let outputs = outputs(&[4, 6]);
        let seed = [0x5E; 32];
        let blinds = PseudoOutBlinds::seeded(&seed, inputs(3), &outputs).into_bytes();
        let mut stream = rand_chacha::ChaCha20Rng::from_seed(seed);
        let drawn = [(); 2].map(|()| Scalar::random(&mut stream).to_bytes());
        assert_eq!(*blinds[0], drawn[0]);
        assert_eq!(*blinds[1], drawn[1]);
        let again = PseudoOutBlinds::seeded(&seed, inputs(3), &outputs).into_bytes();
        assert!(blinds.iter().zip(&again).all(|(a, b)| **a == **b));
        assert_eq!(
            sum(PseudoOutBlinds::seeded(&seed, inputs(3), &outputs)),
            Scalar::from(10u64)
        );
    }
}
