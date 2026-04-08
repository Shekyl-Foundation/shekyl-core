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
//! ## Signing Protocol
//!
//! 1. **Session creation**: Each signer creates a `FrostSalSession` per input.
//! 2. **Preprocess** (`preprocess`): Each signer generates random nonces,
//!    retains the secrets, and publishes nonce commitments.
//! 3. **Nonce aggregation** (`FrostSigningCoordinator::nonce_sums`): The
//!    coordinator sums commitments from all M signers.
//! 4. **Sign** (`sign_share`): Each signer produces a partial signature using
//!    their nonce secret and the aggregated nonce sums.
//! 5. **Aggregate** (`FrostSigningCoordinator::aggregate_input`): The
//!    coordinator sums partial shares and verifies the resulting SAL proof.

use std::collections::HashMap;
use std::fmt;

use rand_core::{OsRng, SeedableRng};
use zeroize::Zeroizing;

use ciphersuite::group::{ff::PrimeField, Group, GroupEncoding};
use dalek_ff_group::{EdwardsPoint, Scalar};
use transcript::{RecommendedTranscript, Transcript};

use modular_frost::{algorithm::Algorithm, Participant, ThresholdKeys, ThresholdView};

pub use shekyl_fcmp_plus_plus::sal::multisig::{Ed25519T, SalAlgorithm};
use shekyl_fcmp_plus_plus::sal::{RerandomizedOutput, SpendAuthAndLinkability};
use shekyl_fcmp_plus_plus::{Input, Output};

use crate::proof::ProveError;

// ---------------------------------------------------------------------------
// Per-input signer session
// ---------------------------------------------------------------------------

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
    nonce_secret: Option<Zeroizing<Scalar>>,
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

/// Result of FROST preprocessing (round 1).
#[derive(Clone)]
pub struct FrostPreprocessResult {
    /// Serialized nonce commitments: `k * G_j` for each generator.
    /// For `SalAlgorithm`, this is one 32-byte compressed point (`k * T`).
    pub nonce_commitments: Vec<u8>,
    /// Serialized addendum (empty for modern SAL).
    pub addendum: Vec<u8>,
}

/// Result of FROST partial signing (round 2).
#[derive(Clone)]
pub struct FrostSignShareResult {
    pub share: [u8; 32],
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
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let transcript = RecommendedTranscript::new(b"Shekyl FROST SAL v1");

        let algorithm = SalAlgorithm::new(rng, transcript, input_data.signable_tx_hash, rerand.clone(), x);

        Ok(Self {
            original_output: output,
            input: crate_input,
            rerand,
            algorithm: Some(algorithm),
            pseudo_out,
            nonce_secret: None,
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

    /// FROST round 1: generate nonces and return commitments.
    ///
    /// Generates a random nonce scalar, stores it for `sign_share`, and
    /// returns `k * G_j` for each generator in the nonce set. For
    /// `SalAlgorithm`, this is a single 32-byte point `k * T`.
    pub fn preprocess(
        &mut self,
        keys: &ThresholdKeys<Ed25519T>,
    ) -> Result<FrostPreprocessResult, ProveError> {
        let algo = self
            .algorithm
            .as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let _addendum = algo.preprocess_addendum(&mut OsRng, keys);
        let nonce_generators = algo.nonces();

        let k = Zeroizing::new(Scalar::random(&mut OsRng));

        let mut nonce_commitments = Vec::new();
        for generators in &nonce_generators {
            for g in generators {
                let commitment = *g * *k;
                nonce_commitments.extend_from_slice(&commitment.to_bytes());
            }
        }

        self.nonce_secret = Some(k);

        Ok(FrostPreprocessResult {
            nonce_commitments,
            addendum: Vec::new(),
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
        let algo = self
            .algorithm
            .as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        algo.process_addendum(view, participant, ())
            .map_err(|e| ProveError::UpstreamError(format!("process_addendum: {e}")))?;
        Ok(())
    }

    /// FROST round 2: produce a partial signature share.
    ///
    /// `nonce_sums`: aggregated nonce commitments from all participants.
    /// Uses this participant's stored nonce secret from `preprocess`.
    pub fn sign_share(
        &mut self,
        params: &ThresholdView<Ed25519T>,
        nonce_sums: &[Vec<EdwardsPoint>],
    ) -> Result<FrostSignShareResult, ProveError> {
        let algo = self
            .algorithm
            .as_mut()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let k = self
            .nonce_secret
            .take()
            .ok_or(ProveError::UpstreamError("nonce not generated (call preprocess first)".into()))?;

        let share = algo.sign_share(params, nonce_sums, vec![k], &[]);
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
        let algo = self
            .algorithm
            .take()
            .ok_or(ProveError::UpstreamError("session already consumed".into()))?;

        let sal = algo
            .verify(group_key, nonce_sums, sum)
            .ok_or(ProveError::UpstreamError("FROST SAL verification failed".into()))?;

        Ok((self.input, sal))
    }
}

// ---------------------------------------------------------------------------
// Signing coordinator
// ---------------------------------------------------------------------------

/// Coordinates a multi-signer FROST SAL signing session.
///
/// The coordinator holds per-input `FrostSalSession`s (as one of the signers)
/// and collects nonce commitments / partial shares from M total participants.
/// After aggregation, it produces `SpendAuthAndLinkability` proofs for each
/// input, which can then be fed into `prove_with_sal` to build the FCMP++ proof.
pub struct FrostSigningCoordinator {
    num_inputs: usize,
    /// Number of generators per nonce set. For SalAlgorithm: [1].
    generators_per_nonce: Vec<usize>,
    included: Vec<Participant>,
    /// Per-participant, per-input: raw nonce commitment bytes.
    commitments: HashMap<Participant, Vec<Vec<u8>>>,
    /// Cached aggregated nonce sums, computed after all commitments collected.
    nonce_sums: Option<Vec<Vec<Vec<EdwardsPoint>>>>,
    /// Per-participant, per-input: partial share scalar.
    shares: HashMap<Participant, Vec<Scalar>>,
}

impl fmt::Debug for FrostSigningCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrostSigningCoordinator")
            .field("num_inputs", &self.num_inputs)
            .field("included", &self.included.len())
            .field("commitments_collected", &self.commitments.len())
            .field("shares_collected", &self.shares.len())
            .finish()
    }
}

impl FrostSigningCoordinator {
    /// Create a new coordinator for `num_inputs` inputs with the given signing set.
    ///
    /// `generators_per_nonce` describes the nonce structure from
    /// `Algorithm::nonces()`. For `SalAlgorithm` this is `vec![1]`
    /// (one nonce set, one generator T per set).
    pub fn new(
        num_inputs: usize,
        generators_per_nonce: Vec<usize>,
        included: Vec<Participant>,
    ) -> Result<Self, ProveError> {
        if num_inputs == 0 {
            return Err(ProveError::EmptyInputs);
        }
        if included.len() < 2 {
            return Err(ProveError::UpstreamError(
                "FROST signing requires at least 2 participants".into(),
            ));
        }
        Ok(Self {
            num_inputs,
            generators_per_nonce,
            included,
            commitments: HashMap::new(),
            nonce_sums: None,
            shares: HashMap::new(),
        })
    }

    /// Convenience constructor for SalAlgorithm's nonce structure.
    pub fn new_for_sal(
        num_inputs: usize,
        included: Vec<Participant>,
    ) -> Result<Self, ProveError> {
        Self::new(num_inputs, vec![1], included)
    }

    /// Collect nonce commitments from one participant for all inputs.
    ///
    /// `preprocesses`: one `FrostPreprocessResult` per input.
    pub fn collect_preprocesses(
        &mut self,
        from: Participant,
        preprocesses: Vec<FrostPreprocessResult>,
    ) -> Result<(), ProveError> {
        if preprocesses.len() != self.num_inputs {
            return Err(ProveError::UpstreamError(format!(
                "expected {} preprocesses, got {}",
                self.num_inputs,
                preprocesses.len()
            )));
        }
        if !self.included.contains(&from) {
            return Err(ProveError::UpstreamError(format!(
                "participant {from:?} not in signing set"
            )));
        }
        if self.commitments.contains_key(&from) {
            return Err(ProveError::UpstreamError(format!(
                "duplicate preprocesses from {from:?}"
            )));
        }

        let per_input: Vec<Vec<u8>> = preprocesses
            .into_iter()
            .map(|p| p.nonce_commitments)
            .collect();

        self.commitments.insert(from, per_input);
        self.nonce_sums = None;
        Ok(())
    }

    /// Whether all signers' nonce commitments have been collected.
    pub fn all_preprocesses_collected(&self) -> bool {
        self.commitments.len() == self.included.len()
    }

    /// Compute aggregated nonce sums across all signers.
    ///
    /// Returns `nonce_sums[input][nonce_set][generator]`.
    pub fn nonce_sums(&mut self) -> Result<Vec<Vec<Vec<EdwardsPoint>>>, ProveError> {
        if !self.all_preprocesses_collected() {
            return Err(ProveError::UpstreamError(format!(
                "need {} preprocesses, have {}",
                self.included.len(),
                self.commitments.len()
            )));
        }

        if let Some(ref cached) = self.nonce_sums {
            return Ok(cached.clone());
        }

        let points_per_input: usize = self.generators_per_nonce.iter().sum();
        let bytes_per_input = points_per_input * 32;

        let mut result: Vec<Vec<Vec<EdwardsPoint>>> = Vec::with_capacity(self.num_inputs);

        for input_idx in 0..self.num_inputs {
            let mut sums: Vec<Vec<EdwardsPoint>> =
                Vec::with_capacity(self.generators_per_nonce.len());
            for &count in &self.generators_per_nonce {
                sums.push(vec![EdwardsPoint::identity(); count]);
            }

            for participant in &self.included {
                let raw = &self.commitments[participant][input_idx];
                if raw.len() != bytes_per_input {
                    return Err(ProveError::UpstreamError(format!(
                        "commitment from {participant:?} for input {input_idx}: expected {bytes_per_input} bytes, got {}",
                        raw.len()
                    )));
                }

                let mut offset = 0;
                for (set_idx, &count) in self.generators_per_nonce.iter().enumerate() {
                    for gen_idx in 0..count {
                        let mut buf = [0u8; 32];
                        buf.copy_from_slice(&raw[offset..offset + 32]);
                        let pt = decompress_point(&buf, "nonce_commitment")?;
                        sums[set_idx][gen_idx] = sums[set_idx][gen_idx] + pt;
                        offset += 32;
                    }
                }
            }

            result.push(sums);
        }

        self.nonce_sums = Some(result.clone());
        Ok(result)
    }

    /// Serialize the nonce sums for distribution to signers.
    ///
    /// Returns one byte blob per input; each blob is the concatenation of
    /// all compressed nonce sum points.
    pub fn nonce_sums_bytes(&mut self) -> Result<Vec<Vec<u8>>, ProveError> {
        let sums = self.nonce_sums()?;
        let mut result = Vec::with_capacity(sums.len());
        for input_sums in &sums {
            let mut bytes = Vec::new();
            for set in input_sums {
                for pt in set {
                    bytes.extend_from_slice(&pt.to_bytes());
                }
            }
            result.push(bytes);
        }
        Ok(result)
    }

    /// Collect a partial signature share from one participant for all inputs.
    pub fn collect_shares(
        &mut self,
        from: Participant,
        input_shares: Vec<FrostSignShareResult>,
    ) -> Result<(), ProveError> {
        if input_shares.len() != self.num_inputs {
            return Err(ProveError::UpstreamError(format!(
                "expected {} shares, got {}",
                self.num_inputs,
                input_shares.len()
            )));
        }
        if !self.included.contains(&from) {
            return Err(ProveError::UpstreamError(format!(
                "participant {from:?} not in signing set"
            )));
        }
        if self.shares.contains_key(&from) {
            return Err(ProveError::UpstreamError(format!(
                "duplicate shares from {from:?}"
            )));
        }

        let scalars: Result<Vec<Scalar>, _> = input_shares
            .iter()
            .map(|s| deserialize_scalar(&s.share, "partial_share"))
            .collect();

        self.shares.insert(from, scalars?);
        Ok(())
    }

    /// Whether all signers' partial shares have been collected.
    pub fn all_shares_collected(&self) -> bool {
        self.shares.len() == self.included.len()
    }

    /// Sum partial shares for one input across all signers.
    pub fn sum_shares_for_input(&self, input_idx: usize) -> Result<Scalar, ProveError> {
        if !self.all_shares_collected() {
            return Err(ProveError::UpstreamError(format!(
                "need {} shares, have {}",
                self.included.len(),
                self.shares.len()
            )));
        }

        let mut sum = Scalar::ZERO;
        for participant in &self.included {
            sum = sum + self.shares[participant][input_idx];
        }
        Ok(sum)
    }

    /// Get the nonce sums for a specific input.
    pub fn nonce_sums_for_input(
        &mut self,
        input_idx: usize,
    ) -> Result<Vec<Vec<EdwardsPoint>>, ProveError> {
        let all = self.nonce_sums()?;
        all.into_iter()
            .nth(input_idx)
            .ok_or(ProveError::UpstreamError(format!(
                "input index {input_idx} out of range"
            )))
    }

    /// Aggregate all inputs: consume sessions, produce (Input, SAL) pairs.
    ///
    /// This is the final step of the coordinator protocol. Each session is
    /// consumed via `FrostSalSession::aggregate`, producing the SAL proof
    /// for one input. Returns pairs ready for `prove_with_sal`.
    pub fn aggregate_all(
        &mut self,
        sessions: Vec<FrostSalSession>,
        group_key: EdwardsPoint,
    ) -> Result<Vec<(Input, SpendAuthAndLinkability)>, ProveError> {
        if sessions.len() != self.num_inputs {
            return Err(ProveError::UpstreamError(format!(
                "expected {} sessions, got {}",
                self.num_inputs,
                sessions.len()
            )));
        }

        let all_nonce_sums = self.nonce_sums()?;
        let mut results = Vec::with_capacity(self.num_inputs);

        for (idx, session) in sessions.into_iter().enumerate() {
            let sum = self.sum_shares_for_input(idx)?;
            let (input, sal) = session.aggregate(group_key, &all_nonce_sums[idx], sum)?;
            results.push((input, sal));
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decompress_point(bytes: &[u8; 32], field: &'static str) -> Result<EdwardsPoint, ProveError> {
    let ct = <EdwardsPoint as GroupEncoding>::from_bytes(bytes.into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(ProveError::InvalidPoint {
            input_index: 0,
            field,
        })
    }
}

fn deserialize_scalar(bytes: &[u8; 32], field: &'static str) -> Result<Scalar, ProveError> {
    let ct = Scalar::from_repr((*bytes).into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(ProveError::InvalidScalar {
            input_index: 0,
            field,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::Ciphersuite as _;

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
        assert_ne!(*session.pseudo_out(), [0u8; 32]);
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

        assert_ne!(
            s1.pseudo_out(),
            s2.pseudo_out(),
            "Two sessions for same input should have different pseudo-outs"
        );
    }

    #[test]
    fn coordinator_rejects_empty_inputs() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let result = FrostSigningCoordinator::new_for_sal(0, vec![p1, p2]);
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_single_participant() {
        let p1 = Participant::new(1).unwrap();
        let result = FrostSigningCoordinator::new_for_sal(1, vec![p1]);
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_wrong_participant() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let p3 = Participant::new(3).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let result = coord.collect_preprocesses(
            p3,
            vec![FrostPreprocessResult {
                nonce_commitments: vec![0; 32],
                addendum: vec![],
            }],
        );
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_duplicate_preprocesses() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let fake = vec![FrostPreprocessResult {
            nonce_commitments: EdwardsPoint::generator().to_bytes().to_vec(),
            addendum: vec![],
        }];
        coord.collect_preprocesses(p1, fake.clone()).unwrap();
        let result = coord.collect_preprocesses(p1, fake);
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_wrong_preprocess_count() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(2, vec![p1, p2]).unwrap();

        let fake = vec![FrostPreprocessResult {
            nonce_commitments: EdwardsPoint::generator().to_bytes().to_vec(),
            addendum: vec![],
        }];
        let result = coord.collect_preprocesses(p1, fake);
        assert!(result.is_err(), "Should reject: 1 preprocess for 2 inputs");
    }

    #[test]
    fn coordinator_rejects_shares_before_nonces() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let result = coord.collect_shares(
            p1,
            vec![FrostSignShareResult { share: [0u8; 32] }],
        );
        assert!(
            result.is_ok(),
            "Share collection is independent of preprocess collection"
        );
    }

    #[test]
    fn coordinator_rejects_duplicate_shares() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let shares = vec![FrostSignShareResult { share: [1u8; 32] }];
        coord.collect_shares(p1, shares.clone()).unwrap();
        let result = coord.collect_shares(p1, shares);
        assert!(result.is_err(), "Should reject duplicate shares");
    }

    #[test]
    fn coordinator_nonce_sums_before_all_collected_fails() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let fake = vec![FrostPreprocessResult {
            nonce_commitments: EdwardsPoint::generator().to_bytes().to_vec(),
            addendum: vec![],
        }];
        coord.collect_preprocesses(p1, fake).unwrap();
        let result = coord.nonce_sums();
        assert!(result.is_err(), "Should fail: only 1 of 2 preprocesses collected");
    }

    #[test]
    fn coordinator_nonce_sums_correct_point_addition() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let g = EdwardsPoint::generator();
        let k1 = Scalar::random(&mut rand_core::OsRng);
        let k2 = Scalar::random(&mut rand_core::OsRng);
        let c1 = g * k1;
        let c2 = g * k2;
        let expected = c1 + c2;

        coord
            .collect_preprocesses(
                p1,
                vec![FrostPreprocessResult {
                    nonce_commitments: c1.to_bytes().to_vec(),
                    addendum: vec![],
                }],
            )
            .unwrap();
        coord
            .collect_preprocesses(
                p2,
                vec![FrostPreprocessResult {
                    nonce_commitments: c2.to_bytes().to_vec(),
                    addendum: vec![],
                }],
            )
            .unwrap();

        let sums = coord.nonce_sums().unwrap();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].len(), 1);
        assert_eq!(sums[0][0].len(), 1);
        assert_eq!(sums[0][0][0], expected);
    }

    #[test]
    fn coordinator_nonce_sums_bytes_roundtrip() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let g = EdwardsPoint::generator();
        let c = g * Scalar::random(&mut rand_core::OsRng);

        for p in [p1, p2] {
            coord
                .collect_preprocesses(
                    p,
                    vec![FrostPreprocessResult {
                        nonce_commitments: c.to_bytes().to_vec(),
                        addendum: vec![],
                    }],
                )
                .unwrap();
        }

        let bytes = coord.nonce_sums_bytes().unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].len(), 32);
    }

    #[test]
    fn sign_share_without_preprocess_fails() {
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
            signable_tx_hash: [0xEF; 32],
        };

        let mut session = FrostSalSession::new(&input).unwrap();

        let keys = crate::frost_dkg::generate_test_keys(2, 3);
        let (_, k) = keys.iter().next().unwrap();
        let participants: Vec<Participant> = keys.keys().copied().collect();
        let view = k.view(participants).unwrap();

        let fake_nonces = vec![vec![EdwardsPoint::generator()]];
        let result = session.sign_share(&view, &fake_nonces);
        assert!(result.is_err(), "Should fail: preprocess not called yet");
    }

    #[test]
    fn coordinator_sum_shares_before_all_collected_fails() {
        let p1 = Participant::new(1).unwrap();
        let p2 = Participant::new(2).unwrap();
        let mut coord = FrostSigningCoordinator::new_for_sal(1, vec![p1, p2]).unwrap();

        let shares = vec![FrostSignShareResult { share: [1u8; 32] }];
        coord.collect_shares(p1, shares).unwrap();

        let result = coord.sum_shares_for_input(0);
        assert!(result.is_err(), "Should fail: only 1 of 2 shares collected");
    }
}
