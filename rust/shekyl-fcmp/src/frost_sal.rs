// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FROST threshold SAL (Spend-Auth-and-Linkability) for FCMP++ multisig.
//!
//! Wraps the upstream `SalAlgorithm` from `shekyl-fcmp-plus-plus` to provide
//! a session-based interface for multi-round FROST signing. The coordinator
//! holds the spend secret `x`; only the view key `y` is threshold-shared
//! via `ThresholdKeys<Ed25519T>`.
//!
//! Protocol:
//! 1. `FrostSalSession::new()` -- initialize per-input session
//! 2. `preprocess()` -- generate FROST nonces + commitments
//! 3. `process_addendum()` -- process each peer's addendum (no-op for modern SAL)
//! 4. `sign_share()` -- produce partial FROST signature share
//! 5. `aggregate()` -- coordinator combines M shares into final SAL proof

use std::fmt;

use rand_core::{OsRng, RngCore, SeedableRng};
use zeroize::Zeroizing;

use ciphersuite::group::{ff::PrimeField, GroupEncoding};
use dalek_ff_group::{EdwardsPoint, Scalar};
use transcript::{RecommendedTranscript, Transcript};

use modular_frost::{algorithm::Algorithm, Participant, ThresholdKeys, ThresholdView};

pub use shekyl_fcmp_plus_plus::sal::multisig::{Ed25519T, SalAlgorithm};
use shekyl_fcmp_plus_plus::{Input, Output};
use shekyl_fcmp_plus_plus::sal::{RerandomizedOutput, SpendAuthAndLinkability};

use crate::proof::ProveError;

/// Opaque session state for one input's FROST SAL signing.
///
/// The spend secret `x` is passed into `SalAlgorithm` at construction and
/// is not retained as a separate field. When the session is dropped, the
/// algorithm (and its internal copy of `x`) is dropped with it.
pub struct FrostSalSession {
    original_output: Output,
    rerand: RerandomizedOutput,
    input: Input,
    algorithm: Option<SalAlgorithm<rand_chacha::ChaCha20Rng, RecommendedTranscript>>,
    pseudo_out: [u8; 32],
}

impl fmt::Debug for FrostSalSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrostSalSession").finish_non_exhaustive()
    }
}

/// Per-input output data needed to initialize a FROST SAL session.
pub struct FrostSalInput {
    pub output_key: [u8; 32],
    pub key_image_gen: [u8; 32],
    pub commitment: [u8; 32],
    pub spend_key_x: [u8; 32],
    pub signable_tx_hash: [u8; 32],
}

impl FrostSalSession {
    /// Create a new FROST SAL session for one input.
    ///
    /// The coordinator must hold `x` (spend secret). The FROST protocol will
    /// threshold-share `y` across participants using `ThresholdKeys<Ed25519T>`.
    #[allow(non_snake_case)]
    pub fn new(input_data: &FrostSalInput) -> Result<Self, ProveError> {
        let O = decompress_point(&input_data.output_key, "output_key")?;
        let I = decompress_point(&input_data.key_image_gen, "key_image_gen")?;
        let C = decompress_point(&input_data.commitment, "commitment")?;
        let x = deserialize_scalar(&input_data.spend_key_x, "spend_key_x")?;

        let output = Output::new(O, I, C)
            .map_err(|e| ProveError::UpstreamError(format!("Output::new: {e:?}")))?;

        let rerand = RerandomizedOutput::new(&mut OsRng, output);
        let crate_input = rerand.input();
        let pseudo_out = crate_input.C_tilde().to_bytes();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let transcript = RecommendedTranscript::new(b"Shekyl FROST SAL v1");

        let algorithm = SalAlgorithm::new(
            rng,
            transcript,
            input_data.signable_tx_hash,
            rerand.clone(),
            x,
        );

        Ok(Self {
            original_output: output,
            input: crate_input,
            rerand,
            algorithm: Some(algorithm),
            pseudo_out,
        })
    }

    /// The rerandomized commitment (pseudo-out) for this input.
    pub fn pseudo_out(&self) -> &[u8; 32] {
        &self.pseudo_out
    }

    /// The `Input` (rerandomized tuple) for downstream proof construction.
    pub fn input(&self) -> &Input {
        &self.input
    }

    /// The `RerandomizedOutput` for downstream proof construction.
    pub fn rerandomized_output(&self) -> &RerandomizedOutput {
        &self.rerand
    }

    /// The original (non-rerandomized) `Output` for path construction.
    pub fn original_output(&self) -> &Output {
        &self.original_output
    }

    /// FROST round 1: generate nonces and preprocessing addendum.
    ///
    /// For `SalAlgorithm`, the addendum is `()` (no data to exchange beyond
    /// nonce commitments). Returns the serialized nonce commitments.
    pub fn preprocess(
        &mut self,
        keys: &ThresholdKeys<Ed25519T>,
    ) -> Result<FrostPreprocessResult, ProveError> {
        let algo = self.algorithm.as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let _addendum = algo.preprocess_addendum(&mut OsRng, keys);
        let nonce_generators = algo.nonces();

        let mut nonce_commitments = Vec::new();
        for generators in &nonce_generators {
            for g in generators {
                nonce_commitments.extend_from_slice(&g.to_bytes());
            }
        }

        Ok(FrostPreprocessResult {
            nonce_commitments,
            addendum: Vec::new(), // () serialized as empty
        })
    }

    /// FROST round 1 continued: process a peer's addendum.
    ///
    /// For modern `SalAlgorithm`, this is a no-op (addendum is `()`).
    pub fn process_addendum(
        &mut self,
        view: &ThresholdView<Ed25519T>,
        participant: Participant,
    ) -> Result<(), ProveError> {
        let algo = self.algorithm.as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        algo.process_addendum(view, participant, ())
            .map_err(|e| ProveError::UpstreamError(format!("process_addendum: {e}")))?;
        Ok(())
    }

    /// FROST round 2: produce a partial signature share.
    ///
    /// `nonce_sums`: aggregated nonce commitments from all participants.
    /// `nonces`: this participant's secret nonces from preprocessing.
    pub fn sign_share(
        &mut self,
        params: &ThresholdView<Ed25519T>,
        nonce_sums: &[Vec<EdwardsPoint>],
        nonces: Vec<Zeroizing<Scalar>>,
    ) -> Result<FrostSignShareResult, ProveError> {
        let algo = self.algorithm.as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let share = algo.sign_share(params, nonce_sums, nonces, &[]);
        Ok(FrostSignShareResult {
            share: share.to_repr().into(),
        })
    }

    /// Aggregate M partial shares into a final `SpendAuthAndLinkability` proof.
    ///
    /// Consumes the session. The caller (coordinator) provides the aggregated
    /// FROST signature scalar `sum` (sum of M partial shares).
    pub fn aggregate(
        mut self,
        group_key: EdwardsPoint,
        nonce_sums: &[Vec<EdwardsPoint>],
        sum: Scalar,
    ) -> Result<(Input, SpendAuthAndLinkability), ProveError> {
        let algo = self.algorithm.take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let sal = algo.verify(group_key, nonce_sums, sum)
            .ok_or(ProveError::UpstreamError("FROST SAL verification failed".into()))?;

        Ok((self.input, sal))
    }
}

/// Result of FROST preprocessing (round 1).
pub struct FrostPreprocessResult {
    pub nonce_commitments: Vec<u8>,
    pub addendum: Vec<u8>,
}

/// Result of FROST partial signing (round 2).
pub struct FrostSignShareResult {
    pub share: [u8; 32],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decompress_point(bytes: &[u8; 32], field: &'static str) -> Result<EdwardsPoint, ProveError> {
    let ct = <EdwardsPoint as GroupEncoding>::from_bytes(bytes.into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(ProveError::InvalidPoint { input_index: 0, field })
    }
}

fn deserialize_scalar(bytes: &[u8; 32], field: &'static str) -> Result<Scalar, ProveError> {
    let ct = Scalar::from_repr((*bytes).into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(ProveError::InvalidScalar { input_index: 0, field })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::Ciphersuite as _;
    use ciphersuite::group::{Group, GroupEncoding};

    #[test]
    fn frost_sal_session_rejects_identity_points() {
        let input = FrostSalInput {
            output_key: [0; 32],
            key_image_gen: [0; 32],
            commitment: [0; 32],
            spend_key_x: [0; 32],
            signable_tx_hash: [0; 32],
        };
        let result = FrostSalSession::new(&input);
        assert!(result.is_err());
    }

    #[test]
    fn frost_sal_session_creates_with_valid_points() {
        let x = Scalar::random(&mut rand_core::OsRng);
        let g = Ed25519T::generator();

        let o = g * x;
        let i = EdwardsPoint::random(&mut rand_core::OsRng);
        let c = EdwardsPoint::random(&mut rand_core::OsRng);

        let input = FrostSalInput {
            output_key: o.to_bytes().into(),
            key_image_gen: i.to_bytes().into(),
            commitment: c.to_bytes().into(),
            spend_key_x: x.to_repr().into(),
            signable_tx_hash: [0xAB; 32],
        };

        let session = FrostSalSession::new(&input);
        assert!(session.is_ok(), "Session creation failed: {:?}", session.err());

        let session = session.unwrap();

        assert_ne!(*session.pseudo_out(), [0u8; 32], "Pseudo-out should be non-zero");

        // Verify rerandomized output is accessible
        let _rerand = session.rerandomized_output();

        // Verify original output is accessible
        let _orig = session.original_output();
    }

    #[test]
    fn frost_sal_session_produces_distinct_pseudo_outs() {
        let x = Scalar::random(&mut rand_core::OsRng);
        let g = Ed25519T::generator();
        let o = g * x;
        let i = EdwardsPoint::random(&mut rand_core::OsRng);
        let c = EdwardsPoint::random(&mut rand_core::OsRng);

        let input = FrostSalInput {
            output_key: o.to_bytes().into(),
            key_image_gen: i.to_bytes().into(),
            commitment: c.to_bytes().into(),
            spend_key_x: x.to_repr().into(),
            signable_tx_hash: [0xCD; 32],
        };

        let s1 = FrostSalSession::new(&input).unwrap();
        let s2 = FrostSalSession::new(&input).unwrap();

        // Pseudo-outs should differ due to randomized blinding
        assert_ne!(s1.pseudo_out(), s2.pseudo_out(),
            "Two sessions for same input should have different pseudo-outs");
    }

    #[test]
    fn frost_sal_input_fields_roundtrip() {
        let input = FrostSalInput {
            output_key: [1; 32],
            key_image_gen: [2; 32],
            commitment: [3; 32],
            spend_key_x: [4; 32],
            signable_tx_hash: [5; 32],
        };

        assert_eq!(input.output_key, [1; 32]);
        assert_eq!(input.key_image_gen, [2; 32]);
        assert_eq!(input.commitment, [3; 32]);
        assert_eq!(input.spend_key_x, [4; 32]);
        assert_eq!(input.signable_tx_hash, [5; 32]);
    }
}
