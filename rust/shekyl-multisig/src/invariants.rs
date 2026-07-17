// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Honest-signer invariant checks (PQC_MULTISIG.md §2.7).
//!
//! These are the mandatory checks every honest signer performs before
//! producing a signature share. Failure of any check aborts signing,
//! publishes an InvariantViolation, and moves the intent to REJECTED.
//!
//! The invariants are numbered I1–I7 per the spec:
//!
//! - I1: SpendIntent structural + group binding (§9.2)
//! - I2: Chain state fingerprint agreement (§9.3)
//! - I3: FCMP++ proof verification against signing_payload
//! - I4: BP+ proof deterministic match (§10.2)
//! - I7: Receive-time output validation (§8.3, enforced at scan time)
//!
//! I5 (prover assignment) and I6 (assembly consensus) belonged to the
//! Option-D prover lineage and were excised with it under R1-F-6; Option E′
//! (§15.4a) rewrites the spend-time and assembly-time checks fresh under
//! MS-5, so the `InvariantId` discriminants 5 and 6 are intentionally left
//! as gaps here (this enum is internal and never serialized — see below).

use shekyl_units::AtomicUnits;

/// Invariant identifiers for InvariantViolation messages.
///
/// This enum is internal to honest-signer abort reporting and is **never
/// serialized** (no `Serialize`/`Deserialize`; its wire consumer went out
/// with the Option-D `InvariantViolation` struct). Discriminants 5 and 6
/// (former I5/I6) are therefore free to remain gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InvariantId {
    I1SpendIntentValidation = 1,
    I2ChainStateFingerprint = 2,
    I3FcmpProofVerification = 3,
    I4BpPlusDeterministic = 4,
    I7ReceiveTimeValidation = 7,
}

impl InvariantId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::I1SpendIntentValidation),
            2 => Some(Self::I2ChainStateFingerprint),
            3 => Some(Self::I3FcmpProofVerification),
            4 => Some(Self::I4BpPlusDeterministic),
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

/// Input to the invariant pipeline for a single intent.
///
/// The caller provides all locally-derived values; the invariant checks
/// compare them against the proposed intent.
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
    pub input_amounts: &'a [AtomicUnits],
    /// Set of seen kem_randomness_seeds (for replay detection).
    pub seen_kem_seeds: &'a std::collections::HashSet<[u8; 32]>,
    /// Locally recomputed BP+ proof bytes for deterministic match.
    pub local_bp_plus_bytes: &'a [u8],
    /// The proposed BP+ proof bytes to check for deterministic match.
    pub proposed_bp_plus_bytes: &'a [u8],
}

/// Run the pre-signing invariant pipeline (I1, I2, I4).
///
/// I3 (FCMP++ verification) is checked against the signing payload elsewhere;
/// I7 (receive-time validation) was enforced at scan time. I5/I6 were removed
/// with the Option-D prover lineage (R1-F-6); E′ reintroduces the spend-time
/// and assembly-time checks under MS-5 (§15.4a).
pub fn check_pre_signing_invariants(
    intent: &super::intent::SpendIntent,
    input: &InvariantCheckInput<'_>,
) -> InvariantCheckResult {
    // I1: SpendIntent structural + group binding (§9.2)
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

    // I2: Chain state fingerprint (§9.3)
    if intent.chain_state_fingerprint != *input.local_chain_state_fingerprint {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I2ChainStateFingerprint,
            evidence: input.local_chain_state_fingerprint.to_vec(),
        };
    }

    // I4: BP+ deterministic match (§10.2)
    if input.local_bp_plus_bytes != input.proposed_bp_plus_bytes {
        return InvariantCheckResult::Fail {
            invariant: InvariantId::I4BpPlusDeterministic,
            evidence: Vec::new(),
        };
    }

    InvariantCheckResult::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{IntentRecipient, SpendIntent, SPEND_INTENT_VERSION};
    use std::collections::HashSet;

    fn test_intent() -> SpendIntent {
        let fp = crate::intent::ChainStateFingerprint {
            reference_block_hash: [0xCC; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![AtomicUnits::from_raw(310)],
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
                amount: AtomicUnits::from_raw(300),
            }],
            fee: AtomicUnits::from_raw(10),
            input_global_indices: vec![42],
            kem_randomness_seed: [0xDD; 32],
            chain_state_fingerprint: chain_fp,
        }
    }

    fn test_input(intent: &SpendIntent) -> InvariantCheckInput<'static> {
        let fp = crate::intent::ChainStateFingerprint {
            reference_block_hash: [0xCC; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![AtomicUnits::from_raw(310)],
        };
        let chain_fp = fp.compute();

        let _ = intent;

        // We leak the boxed values so they live for 'static in tests.
        let group_id = Box::leak(Box::new([0xBB; 32]));
        let ref_hash = Box::leak(Box::new([0xCC; 32]));
        let chain_fp_ref = Box::leak(Box::new(chain_fp));
        let amounts: &'static [AtomicUnits] =
            Box::leak(vec![AtomicUnits::from_raw(310)].into_boxed_slice());
        let seeds: &'static HashSet<[u8; 32]> = Box::leak(Box::new(HashSet::new()));
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
            local_bp_plus_bytes: bp_bytes,
            proposed_bp_plus_bytes: bp_bytes,
        }
    }

    #[test]
    fn pre_signing_passes() {
        let intent = test_intent();
        let input = test_input(&intent);
        assert!(matches!(
            check_pre_signing_invariants(&intent, &input),
            InvariantCheckResult::Pass
        ));
    }

    #[test]
    fn i1_fails_on_group_id_mismatch() {
        let mut intent = test_intent();
        intent.group_id = [0xFF; 32];
        let input = test_input(&intent);
        match check_pre_signing_invariants(&intent, &input) {
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
        let input = test_input(&intent);
        match check_pre_signing_invariants(&intent, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I2ChainStateFingerprint);
            }
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn i4_fails_on_bp_plus_mismatch() {
        let intent = test_intent();
        let mut input = test_input(&intent);
        let different_bp: &'static [u8] = Box::leak(vec![0x22u8; 50].into_boxed_slice());
        input.proposed_bp_plus_bytes = different_bp;
        match check_pre_signing_invariants(&intent, &input) {
            InvariantCheckResult::Fail { invariant, .. } => {
                assert_eq!(invariant, InvariantId::I4BpPlusDeterministic);
            }
            _ => panic!("expected I4 failure"),
        }
    }

    #[test]
    fn invariant_id_roundtrip() {
        for i in [1u8, 2, 3, 4, 7] {
            let id = InvariantId::from_u8(i).unwrap();
            assert_eq!(id as u8, i);
            assert!(!id.description().is_empty());
        }
        // 0 and 8 are out of range; 5/6 were I5ProverAssignment /
        // I6AssemblyConsensus, removed with the Option-D prover lineage.
        for i in [0u8, 5, 6, 8] {
            assert!(InvariantId::from_u8(i).is_none());
        }
    }
}
