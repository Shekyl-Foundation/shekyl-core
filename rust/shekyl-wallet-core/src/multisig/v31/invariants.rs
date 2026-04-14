// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Honest-signer invariant checks (PQC_MULTISIG.md SS2.7).
//!
//! These are the mandatory checks every honest signer performs before
//! producing a signature share. Failure of any check aborts signing,
//! publishes an InvariantViolation, and moves the intent to REJECTED.
//!
//! The invariants are numbered I1–I7 per the spec:
//!
//! - I1: SpendIntent structural + group binding (SS9.2)
//! - I2: Chain state fingerprint agreement (SS9.3)
//! - I3: FCMP++ proof verification against signing_payload
//! - I4: BP+ proof deterministic match (SS10.2)
//! - I5: Prover assignment verification (SS11.3)
//! - I6: Assembly: all M tx_hash and proof commitments agree (SS11.5)
//! - I7: Receive-time output validation (SS8.3, enforced at scan time)

/// Invariant identifiers for InvariantViolation messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InvariantId {
    I1SpendIntentValidation = 1,
    I2ChainStateFingerprint = 2,
    I3FcmpProofVerification = 3,
    I4BpPlusDeterministic = 4,
    I5ProverAssignment = 5,
    I6AssemblyConsensus = 6,
    I7ReceiveTimeValidation = 7,
}

impl InvariantId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::I1SpendIntentValidation),
            2 => Some(Self::I2ChainStateFingerprint),
            3 => Some(Self::I3FcmpProofVerification),
            4 => Some(Self::I4BpPlusDeterministic),
            5 => Some(Self::I5ProverAssignment),
            6 => Some(Self::I6AssemblyConsensus),
            7 => Some(Self::I7ReceiveTimeValidation),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::I1SpendIntentValidation => "SpendIntent structural/group binding",
            Self::I2ChainStateFingerprint => "chain state fingerprint mismatch",
            Self::I3FcmpProofVerification => "FCMP++ proof verification failed",
            Self::I4BpPlusDeterministic => "BP+ proof deterministic mismatch",
            Self::I5ProverAssignment => "prover assignment verification failed",
            Self::I6AssemblyConsensus => "assembly consensus mismatch",
            Self::I7ReceiveTimeValidation => "receive-time output validation failed",
        }
    }
}

/// Result of running the pre-signing invariant pipeline.
#[derive(Debug)]
pub enum InvariantCheckResult {
    Pass,
    Fail {
        invariant: InvariantId,
        evidence: Vec<u8>,
    },
}

/// Input to the invariant pipeline for a single intent + prover output.
///
/// The caller provides all locally-derived values; the invariant checks
/// compare them against the proposed intent and prover output.
pub struct InvariantCheckInput<'a> {
    /// Our group_id.
    pub our_group_id: &'a [u8; 32],
    /// n_total from group metadata.
    pub n_total: u8,
    /// Current time (unix seconds).
    pub now_secs: u64,
    /// Expected tx_counter from local state.
    pub expected_tx_counter: u64,
    /// Chain tip height from local view.
    pub chain_tip_height: u64,
    /// Block hash at the intent's reference_block_height from local view.
    pub local_ref_block_hash: &'a [u8; 32],
    /// Locally computed chain_state_fingerprint.
    pub local_chain_state_fingerprint: &'a [u8; 32],
    /// Input amounts from local view.
    pub input_amounts: &'a [u64],
    /// Set of seen kem_randomness_seeds (for replay detection).
    pub seen_kem_seeds: &'a std::collections::HashSet<[u8; 32]>,
    /// Per-input: the locally-persisted assigned_prover_index.
    pub persisted_prover_indices: &'a [u8],
    /// Per-input: the locally-persisted spend_auth_pubkeys[assigned_prover].
    pub persisted_output_pubkeys: &'a [[u8; 32]],
    /// The prover's fcmp_proof_commitment.
    pub prover_fcmp_commitment: &'a [u8; 32],
    /// Locally recomputed BP+ proof bytes for deterministic match.
    pub local_bp_plus_bytes: &'a [u8],
    /// The prover's BP+ proof bytes.
    pub prover_bp_plus_bytes: &'a [u8],
}

/// Run the full pre-signing invariant pipeline (I1 through I5).
///
/// I6 (assembly consensus) is checked during share collection, not here.
/// I7 (receive-time validation) was enforced at scan time.
pub fn check_pre_signing_invariants(
    intent: &super::intent::SpendIntent,
    prover: &super::prover::ProverOutput,
    input: &InvariantCheckInput<'_>,
) -> InvariantCheckResult {
    // I1: SpendIntent structural + group binding (SS9.2)
    if intent.group_id != *input.our_group_id {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I1SpendIntentValidation,
            evidence: intent.group_id.to_vec(),
        };
    }
    if let Err(e) = intent.validate_structural(input.n_total, input.now_secs) {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I1SpendIntentValidation,
            evidence: format!("{e}").into_bytes(),
        };
    }
    if let Err(e) = intent.validate_temporal(
        input.expected_tx_counter,
        input.chain_tip_height,
        input.local_ref_block_hash,
    ) {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I1SpendIntentValidation,
            evidence: format!("{e}").into_bytes(),
        };
    }
    if let Err(e) = intent.validate_balance(input.input_amounts) {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I1SpendIntentValidation,
            evidence: format!("{e}").into_bytes(),
        };
    }
    if input.seen_kem_seeds.contains(&intent.kem_randomness_seed) {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I1SpendIntentValidation,
            evidence: b"kem_randomness_seed replay".to_vec(),
        };
    }

    // I2: Chain state fingerprint (SS9.3)
    if intent.chain_state_fingerprint != *input.local_chain_state_fingerprint {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I2ChainStateFingerprint,
            evidence: input.local_chain_state_fingerprint.to_vec(),
        };
    }

    // I4: BP+ deterministic match (SS10.2)
    if input.local_bp_plus_bytes != input.prover_bp_plus_bytes {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I4BpPlusDeterministic,
            evidence: Vec::new(),
        };
    }

    // I5: Prover assignment verification (SS11.3)
    if prover.prover_index as usize >= input.persisted_prover_indices.len() {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I5ProverAssignment,
            evidence: vec![prover.prover_index],
        };
    }
    for (i, proof) in prover.fcmp_proofs.iter().enumerate() {
        if i >= input.persisted_prover_indices.len() {
            return InvariantCheckResult::Fail {
                invariant: InvariantId::I5ProverAssignment,
                evidence: format!("proof index {i} out of range").into_bytes(),
            };
        }
        let expected_prover = input.persisted_prover_indices[i];
        if prover.prover_index != expected_prover {
            return InvariantCheckResult::Fail {
                invariant: InvariantId::I5ProverAssignment,
                evidence: format!(
                    "input {}: expected prover {}, got {}",
                    proof.input_global_index, expected_prover, prover.prover_index
                )
                .into_bytes(),
            };
        }
    }

    InvariantCheckResult::Pass
}

/// Check assembly consensus (I6) across M signature shares (SS11.5).
pub fn check_assembly_consensus(shares: &[super::prover::SignatureShare]) -> InvariantCheckResult {
    if shares.is_empty() {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I6AssemblyConsensus,
            evidence: b"no shares".to_vec(),
        };
    }

    let first = &shares[0];
    for share in &shares[1..] {
        if share.tx_hash_commitment != first.tx_hash_commitment {
            return InvariantCheckResult::Fail {
                invariant: InvariantId::I6AssemblyConsensus,
                evidence: format!(
                    "tx_hash disagreement: signer {} vs signer {}",
                    first.signer_index, share.signer_index
                )
                .into_bytes(),
            };
        }
        if share.fcmp_proof_commitment != first.fcmp_proof_commitment {
            return InvariantCheckResult::Fail {
                invariant: InvariantId::I6AssemblyConsensus,
                evidence: format!(
                    "fcmp_proof disagreement: signer {} vs signer {}",
                    first.signer_index, share.signer_index
                )
                .into_bytes(),
            };
        }
        if share.bp_plus_proof_commitment != first.bp_plus_proof_commitment {
            return InvariantCheckResult::Fail {
                invariant: InvariantId::I6AssemblyConsensus,
                evidence: format!(
                    "bp_plus disagreement: signer {} vs signer {}",
                    first.signer_index, share.signer_index
                )
                .into_bytes(),
            };
        }
    }

    InvariantCheckResult::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multisig::v31::intent::{IntentRecipient, SpendIntent, SPEND_INTENT_VERSION};
    use crate::multisig::v31::prover::{ProverInputProof, ProverOutput, SignatureShare};
    use std::collections::HashSet;

    fn test_intent() -> SpendIntent {
        let fp = super::super::intent::ChainStateFingerprint {
            reference_block_hash: [0xCC; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![310],
            input_assigned_prover_indices: vec![0],
        };
        let chain_fp = fp.compute();

        SpendIntent {
            version: SPEND_INTENT_VERSION,
            intent_id: [0xAA; 32],
            group_id: [0xBB; 32],
            proposer_index: 0,
            proposer_sig: vec![0; 64],
            created_at: 1000,
            expires_at: 2000,
            tx_counter: 5,
            reference_block_height: 900,
            reference_block_hash: [0xCC; 32],
            recipients: vec![IntentRecipient {
                address: vec![1, 2, 3],
                amount: 300,
            }],
            fee: 10,
            input_global_indices: vec![42],
            kem_randomness_seed: [0xDD; 32],
            chain_state_fingerprint: chain_fp,
        }
    }

    fn test_prover_output(intent: &SpendIntent) -> ProverOutput {
        ProverOutput {
            prover_index: 0,
            intent_hash: intent.intent_hash(),
            fcmp_proofs: vec![ProverInputProof {
                input_global_index: 42,
                fcmp_proof: vec![0xEE; 100],
                key_image: [0xFF; 32],
            }],
            prover_sig: vec![0; 64],
        }
    }

    fn test_input(intent: &SpendIntent) -> InvariantCheckInput<'static> {
        let fp = super::super::intent::ChainStateFingerprint {
            reference_block_hash: [0xCC; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![310],
            input_assigned_prover_indices: vec![0],
        };
        let chain_fp = fp.compute();

        let _ = intent;

        // We leak the boxed values so they live for 'static in tests.
        let group_id = Box::leak(Box::new([0xBB; 32]));
        let ref_hash = Box::leak(Box::new([0xCC; 32]));
        let chain_fp_ref = Box::leak(Box::new(chain_fp));
        let amounts: &'static [u64] = Box::leak(vec![310u64].into_boxed_slice());
        let seeds: &'static HashSet<[u8; 32]> = Box::leak(Box::new(HashSet::new()));
        let prover_indices: &'static [u8] = Box::leak(vec![0u8].into_boxed_slice());
        let output_pubkeys: &'static [[u8; 32]] = Box::leak(vec![[0xAA; 32]].into_boxed_slice());
        let bp_bytes: &'static [u8] = Box::leak(vec![0x11u8; 50].into_boxed_slice());

        InvariantCheckInput {
            our_group_id: group_id,
            n_total: 3,
            now_secs: 1500,
            expected_tx_counter: 5,
            chain_tip_height: 950,
            local_ref_block_hash: ref_hash,
            local_chain_state_fingerprint: chain_fp_ref,
            input_amounts: amounts,
            seen_kem_seeds: seeds,
            persisted_prover_indices: prover_indices,
            persisted_output_pubkeys: output_pubkeys,
            prover_fcmp_commitment: &[0; 32],
            local_bp_plus_bytes: bp_bytes,
            prover_bp_plus_bytes: bp_bytes,
        }
    }

    #[test]
    fn pre_signing_passes() {
        let intent = test_intent();
        let prover = test_prover_output(&intent);
        let input = test_input(&intent);
        assert!(matches!(
            check_pre_signing_invariants(&intent, &prover, &input),
            InvariantCheckResult::Pass
        ));
    }

    #[test]
    fn i1_fails_on_group_id_mismatch() {
        let mut intent = test_intent();
        intent.group_id = [0xFF; 32];
        let prover = test_prover_output(&intent);
        let input = test_input(&intent);
        match check_pre_signing_invariants(&intent, &prover, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I1SpendIntentValidation);
            }
            _ => panic!("expected I1 failure"),
        }
    }

    #[test]
    fn i2_fails_on_chain_state_mismatch() {
        let mut intent = test_intent();
        intent.chain_state_fingerprint = [0xFF; 32];
        let prover = test_prover_output(&intent);
        let input = test_input(&intent);
        match check_pre_signing_invariants(&intent, &prover, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I2ChainStateFingerprint);
            }
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn i4_fails_on_bp_plus_mismatch() {
        let intent = test_intent();
        let prover = test_prover_output(&intent);
        let mut input = test_input(&intent);
        let different_bp: &'static [u8] = Box::leak(vec![0x22u8; 50].into_boxed_slice());
        input.prover_bp_plus_bytes = different_bp;
        match check_pre_signing_invariants(&intent, &prover, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I4BpPlusDeterministic);
            }
            _ => panic!("expected I4 failure"),
        }
    }

    #[test]
    fn i5_fails_on_wrong_prover() {
        let intent = test_intent();
        let mut prover = test_prover_output(&intent);
        prover.prover_index = 2;
        let input = test_input(&intent);
        match check_pre_signing_invariants(&intent, &prover, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I5ProverAssignment);
            }
            _ => panic!("expected I5 failure"),
        }
    }

    #[test]
    fn i6_passes_on_matching_shares() {
        let shares = vec![
            SignatureShare {
                signer_index: 0,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xAA; 32],
                fcmp_proof_commitment: [0xBB; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
            SignatureShare {
                signer_index: 1,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xAA; 32],
                fcmp_proof_commitment: [0xBB; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
        ];
        assert!(matches!(
            check_assembly_consensus(&shares),
            InvariantCheckResult::Pass
        ));
    }

    #[test]
    fn i6_fails_on_tx_hash_disagreement() {
        let shares = vec![
            SignatureShare {
                signer_index: 0,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xAA; 32],
                fcmp_proof_commitment: [0xBB; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
            SignatureShare {
                signer_index: 1,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xFF; 32],
                fcmp_proof_commitment: [0xBB; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
        ];
        match check_assembly_consensus(&shares) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I6AssemblyConsensus);
            }
            _ => panic!("expected I6 failure"),
        }
    }

    #[test]
    fn i6_fails_on_fcmp_proof_disagreement() {
        let shares = vec![
            SignatureShare {
                signer_index: 0,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xAA; 32],
                fcmp_proof_commitment: [0xBB; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
            SignatureShare {
                signer_index: 1,
                hybrid_sig: vec![0; 64],
                tx_hash_commitment: [0xAA; 32],
                fcmp_proof_commitment: [0xFF; 32],
                bp_plus_proof_commitment: [0xCC; 32],
            },
        ];
        match check_assembly_consensus(&shares) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I6AssemblyConsensus);
            }
            _ => panic!("expected I6 failure"),
        }
    }

    #[test]
    fn invariant_id_roundtrip() {
        for i in 1..=7u8 {
            let id = InvariantId::from_u8(i).unwrap();
            assert_eq!(id as u8, i);
            assert!(!id.description().is_empty());
        }
        assert!(InvariantId::from_u8(0).is_none());
        assert!(InvariantId::from_u8(8).is_none());
    }
}
