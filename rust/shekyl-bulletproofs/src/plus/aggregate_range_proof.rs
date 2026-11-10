use std_shims::{vec, vec::Vec};

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::Identity};

use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::{keccak256_to_scalar, Commitment, INV_EIGHT};

use crate::{
    batch_verifier::{BatchTerms, BulletproofsPlusBatchVerifier},
    core::{multiexp, multiexp_vartime, COMMITMENT_BITS, MAX_COMMITMENTS},
    plus::{
        padded_pow_of_2,
        transcript::*,
        u64_decompose,
        weighted_inner_product::{WipProof, WipStatement, WipVerifierStatement, WipWitness},
        BpPlusGenerators, GeneratorsList, PointVector, ScalarVector,
    },
};

// Figure 3 of the Bulletproofs+ Paper
#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement<'a> {
    generators: BpPlusGenerators,
    V: &'a [EdwardsPoint],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct AggregateRangeWitness(Vec<Commitment>);

impl AggregateRangeWitness {
    pub(crate) fn new(commitments: Vec<Commitment>) -> Option<Self> {
        if commitments.is_empty() || (commitments.len() > MAX_COMMITMENTS) {
            return None;
        }

        Some(AggregateRangeWitness(commitments))
    }
}

/// Internal structure representing a Bulletproof+, as defined by Monero..
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRangeProof {
    pub(crate) A: CompressedPoint,
    pub(crate) wip: WipProof,
}

/// The scalars `Â` is built from, for `padded` commitments (a power of 2):
///
/// `Â = A − z·Σ G_i + Σ d_y_z[i]·H_i + y^(mn+1)·Σ_j z^(2j)·V_j + g_const·g`
///
/// The prover evaluates it ([`AggregateRangeStatement::compute_A_hat`]); the
/// verifier adds its terms into the batch ([`AggregateRangeStatement::A_hat_terms`]).
/// One derivation for both.
struct AHatScalars {
    y: Scalar,
    z: Scalar,
    /// `z², z⁴, …`, one per padded commitment (and one past the last).
    z_pow: ScalarVector,
    /// `d ∘ descending powers of y, + z`: the coefficient of `H_i`.
    d_descending_y_plus_z: ScalarVector,
    y_mn_plus_one: Scalar,
    /// `(Σyⁱ)·z − Σd·y^(mn+1)·z − (Σyⁱ)·z²`: the coefficient of `g`.
    g: Scalar,
}

impl<'a> AggregateRangeStatement<'a> {
    pub(crate) fn new(V: &'a [EdwardsPoint]) -> Option<Self> {
        if V.is_empty() || (V.len() > MAX_COMMITMENTS) {
            return None;
        }

        Some(Self {
            generators: BpPlusGenerators::new(),
            V,
        })
    }

    fn transcript_A(transcript: &mut Scalar, A: CompressedPoint) -> (Scalar, Scalar) {
        let y = keccak256_to_scalar([transcript.to_bytes(), A.to_bytes()].concat());
        let z = keccak256_to_scalar(y.to_bytes());
        *transcript = z;
        (y, z)
    }

    fn d_j(j: usize, m: usize) -> ScalarVector {
        let mut d_j = Vec::with_capacity(m * COMMITMENT_BITS);
        for _ in 0..(j - 1) * COMMITMENT_BITS {
            d_j.push(Scalar::ZERO);
        }
        d_j.append(&mut ScalarVector::powers(Scalar::from(2u8), COMMITMENT_BITS).0);
        for _ in 0..(m - j) * COMMITMENT_BITS {
            d_j.push(Scalar::ZERO);
        }
        ScalarVector(d_j)
    }

    /// Draws `y` and `z` from the transcript and derives [`AHatScalars`].
    fn A_hat_scalars(padded: usize, transcript: &mut Scalar, A: CompressedPoint) -> AHatScalars {
        let (y, z) = Self::transcript_A(transcript, A);

        let mn = padded * COMMITMENT_BITS;

        // 2, 4, 6, 8... powers of z, of length equivalent to the amount of commitments
        let mut z_pow = Vec::with_capacity(padded);
        // z**2
        z_pow.push(z * z);

        let mut d = ScalarVector::new(mn);
        for j in 1..=padded {
            z_pow.push(
                *z_pow
                    .last()
                    .expect("couldn't get last z_pow despite always being non-empty")
                    * z_pow[0],
            );
            d = d + &(Self::d_j(j, padded) * (z_pow[j - 1]));
        }

        let mut ascending_y = ScalarVector(vec![y]);
        for i in 1..d.len() {
            ascending_y.0.push(ascending_y[i - 1] * y);
        }
        let y_pows = ascending_y.clone().sum();

        let mut descending_y = ascending_y.clone();
        descending_y.0.reverse();

        let d_descending_y = d.clone() * &descending_y;
        let d_descending_y_plus_z = d_descending_y + z;

        let y_mn_plus_one = descending_y[0] * y;

        let g = (y_pows * z) - (d.sum() * y_mn_plus_one * z) - (y_pows * (z * z));

        AHatScalars {
            y,
            z,
            z_pow: ScalarVector(z_pow),
            d_descending_y_plus_z,
            y_mn_plus_one,
            g,
        }
    }

    /// The prover's `Â`, evaluated. The scalars are the same record the
    /// verifier adds into the batch ([`Self::A_hat_terms`]).
    fn compute_A_hat(
        mut V: PointVector,
        generators: &BpPlusGenerators,
        transcript: &mut Scalar,
        A: CompressedPoint,
    ) -> Option<(AHatScalars, EdwardsPoint)> {
        while V.len() < padded_pow_of_2(V.len()) {
            V.0.push(EdwardsPoint::identity());
        }

        let scalars = Self::A_hat_scalars(V.len(), transcript, A);
        let A = A.decompress().as_ref().map(EdwardsPoint::mul_by_cofactor)?;

        let mut commitment_accum = EdwardsPoint::identity();
        for (j, commitment) in V.0.iter().enumerate() {
            commitment_accum += *commitment * scalars.z_pow[j];
        }

        let neg_z = -scalars.z;
        let mut A_terms = Vec::with_capacity((generators.len() * 2) + 2);
        for (i, d_y_z) in scalars.d_descending_y_plus_z.0.iter().enumerate() {
            A_terms.push((neg_z, generators.generator(GeneratorsList::GBold, i)));
            A_terms.push((*d_y_z, generators.generator(GeneratorsList::HBold, i)));
        }
        A_terms.push((scalars.y_mn_plus_one, commitment_accum));
        A_terms.push((scalars.g, BpPlusGenerators::g()));

        Some((scalars, A + multiexp_vartime(&A_terms)))
    }

    /// Bold-vector length for `commitments` outputs: the count rounded up to
    /// a power of two, times [`COMMITMENT_BITS`].
    ///
    /// The prover and both verifiers reduce their generators to this
    /// ([`Self::generators_for`]). [`Self::A_hat_terms`] builds `g_bold` and
    /// `h_bold` at it. One length, so a non-power-of-two output count cannot
    /// give the terms a longer vector than the statement has generators.
    fn padded_bold_len(commitments: usize) -> usize {
        padded_pow_of_2(commitments) * COMMITMENT_BITS
    }

    /// [`BpPlusGenerators::reduce`] of [`Self::padded_bold_len`].
    ///
    /// `reduce` rounds a bit-length up to a power of two. This length is
    /// already a power of two when [`COMMITMENT_BITS`] is, and the assert
    /// pins that the view came back at the length the bold vectors use.
    fn generators_for(generators: &BpPlusGenerators, commitments: usize) -> BpPlusGenerators {
        let bold_len = Self::padded_bold_len(commitments);
        let generators = generators.reduce(bold_len);
        debug_assert_eq!(generators.len(), bold_len);
        generators
    }

    /// The verifier's `Â`, as terms over the batch's slots (never evaluated):
    /// `A` and each real commitment in `other`, `−z` on every `G_i`,
    /// `d_y_z[i]` on every `H_i`, and the constant on `g`. `V` is unpadded and
    /// cofactor-cleared; a padding commitment is the identity and contributes
    /// nothing, so it is not a term. `None` if `A` does not decompress.
    fn A_hat_terms(
        V: &[EdwardsPoint],
        transcript: &mut Scalar,
        A: CompressedPoint,
    ) -> Option<(Scalar, BatchTerms)> {
        let padded = padded_pow_of_2(V.len());
        let AHatScalars {
            y,
            z,
            z_pow,
            mut d_descending_y_plus_z,
            y_mn_plus_one,
            g,
        } = Self::A_hat_scalars(padded, transcript, A);

        let A = A.decompress().as_ref().map(EdwardsPoint::mul_by_cofactor)?;

        let mut other = Vec::with_capacity(1 + V.len());
        other.push((Scalar::ONE, A));
        for (j, commitment) in V.iter().enumerate() {
            other.push((y_mn_plus_one * z_pow[j], *commitment));
        }

        let bold_len = Self::padded_bold_len(V.len());
        // `ScalarVector` zeroizes on drop, so the coefficients are taken out.
        let h_bold = core::mem::take(&mut d_descending_y_plus_z.0);
        debug_assert_eq!(h_bold.len(), bold_len);
        Some((
            y,
            BatchTerms {
                g,
                g_bold: vec![-z; bold_len],
                h_bold,
                other,
            },
        ))
    }

    /// The transcript's opening: each commitment times `8⁻¹`, hashed, then
    /// cofactor-cleared so the clear restores the value.
    ///
    /// Commitments are transmitted whole. The transcript hashes the `8⁻¹`
    /// product. The prover and both verifiers call this, and the product is
    /// constant-time, so the transcript does not depend on the path.
    fn prepare_commitments(V: &[EdwardsPoint]) -> (Scalar, Vec<EdwardsPoint>) {
        let scaled = V
            .iter()
            .map(|point| point * INV_EIGHT())
            .collect::<Vec<_>>();
        let transcript = initial_transcript(scaled.iter());
        let cleared = scaled.iter().map(EdwardsPoint::mul_by_cofactor).collect();
        (transcript, cleared)
    }

    /// [`Self::prepare_commitments`], then [`Self::generators_for`] at that
    /// commitment count. Both verifiers open a statement this way. The prover
    /// pads before it reduces, so it calls [`Self::prepare_commitments`] and
    /// [`Self::generators_for`] itself.
    fn open_verifier(
        generators: &BpPlusGenerators,
        V: &[EdwardsPoint],
    ) -> (Scalar, Vec<EdwardsPoint>, BpPlusGenerators) {
        let (transcript, points) = Self::prepare_commitments(V);
        let generators = Self::generators_for(generators, points.len());
        (transcript, points, generators)
    }

    pub(crate) fn prove<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        witness: &AggregateRangeWitness,
    ) -> Option<AggregateRangeProof> {
        // Check for consistency with the witness
        if self.V.len() != witness.0.len() {
            return None;
        }
        for (commitment, witness) in self.V.iter().zip(witness.0.iter()) {
            if witness.calculate() != *commitment {
                return None;
            }
        }

        let Self { generators, V } = self;
        let (mut transcript, mut V) = Self::prepare_commitments(V);

        // Pad V
        while V.len() < padded_pow_of_2(V.len()) {
            V.push(EdwardsPoint::identity());
        }

        let generators = Self::generators_for(&generators, V.len());

        let mut d_js = Vec::with_capacity(V.len());
        let mut a_l = ScalarVector(Vec::with_capacity(V.len() * COMMITMENT_BITS));
        for j in 1..=V.len() {
            d_js.push(Self::d_j(j, V.len()));
            #[allow(clippy::map_unwrap_or)]
            a_l.0.append(
                &mut u64_decompose(
                    *witness
                        .0
                        .get(j - 1)
                        .map(|commitment| &commitment.amount)
                        .unwrap_or(&0),
                )
                .0,
            );
        }

        let a_r = a_l.clone() - Scalar::ONE;

        let alpha = Scalar::random(&mut *rng);

        let mut A_terms = Vec::with_capacity((generators.len() * 2) + 1);
        for (i, a_l) in a_l.0.iter().enumerate() {
            A_terms.push((*a_l, generators.generator(GeneratorsList::GBold, i)));
        }
        for (i, a_r) in a_r.0.iter().enumerate() {
            A_terms.push((*a_r, generators.generator(GeneratorsList::HBold, i)));
        }
        A_terms.push((alpha, BpPlusGenerators::h()));
        let mut A = multiexp(&A_terms);
        A_terms.zeroize();

        // Multiply by INV_EIGHT per earlier commentary
        A *= INV_EIGHT();

        let A = CompressedPoint::from(A.compress());

        let (
            AHatScalars {
                y,
                d_descending_y_plus_z,
                y_mn_plus_one,
                z,
                z_pow,
                ..
            },
            A_hat,
        ) = Self::compute_A_hat(PointVector(V), &generators, &mut transcript, A)
            .expect("A is a valid point as we just compressed it");

        let a_l = a_l - z;
        let a_r = a_r + &d_descending_y_plus_z;
        let mut alpha = alpha;
        for j in 1..=witness.0.len() {
            alpha += z_pow[j - 1] * witness.0[j - 1].mask * y_mn_plus_one;
        }

        Some(AggregateRangeProof {
            A,
            wip: WipStatement::new(generators, A_hat, y)
                .prove(
                    rng,
                    transcript,
                    &Zeroizing::new(
                        WipWitness::new(a_l, a_r, alpha)
                            .expect("Bulletproofs::Plus created an invalid WipWitness"),
                    ),
                )
                .expect("Bulletproof::Plus failed to prove the weighted inner-product"),
        })
    }

    pub(crate) fn verify<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        verifier: &mut BulletproofsPlusBatchVerifier,
        proof: AggregateRangeProof,
    ) -> bool {
        let Self { generators, V } = self;
        let (mut transcript, V, generators) = Self::open_verifier(&generators, V);

        let Some((y, terms)) = Self::A_hat_terms(&V, &mut transcript, proof.A) else {
            return false;
        };
        WipVerifierStatement::new(generators, terms, y).verify(rng, verifier, transcript, proof.wip)
    }

    /// The fold's oracle (`tests::fold`). Evaluates `Â` with its own
    /// multiscalar multiplication, then adds that one point through
    /// [`WipVerifierStatement`] at the weight the folded terms get.
    /// Commitment preparation is [`Self::prepare_commitments`], the same
    /// call [`Self::verify`] makes. Never a production path.
    #[cfg(test)]
    pub(crate) fn verify_eager<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        verifier: &mut BulletproofsPlusBatchVerifier,
        proof: AggregateRangeProof,
    ) -> bool {
        let Self { generators, V } = self;
        let (mut transcript, V, generators) = Self::open_verifier(&generators, V);

        let Some((AHatScalars { y, .. }, a_hat)) =
            Self::compute_A_hat(PointVector(V), &generators, &mut transcript, proof.A)
        else {
            return false;
        };
        WipVerifierStatement::new(generators, BatchTerms::point(a_hat), y)
            .verify(rng, verifier, transcript, proof.wip)
    }
}
