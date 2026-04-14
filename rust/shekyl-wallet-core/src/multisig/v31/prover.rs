// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! ProverOutput and ProverReceipt for V3.1 multisig (PQC_MULTISIG.md SS11, SS12.2).
//!
//! The assigned prover constructs the FCMP++ proof for each input they're
//! responsible for, then publishes a `ProverOutput` to the group. Each
//! signer verifies the proof before producing their signature share.

use serde::{Deserialize, Serialize};

/// ProverOutput: the prover's FCMP++ proof for a set of inputs
/// (PQC_MULTISIG.md SS11.2, SS12.2 message type 0x02).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverOutput {
    pub prover_index: u8,
    pub intent_hash: [u8; 32],
    pub fcmp_proofs: Vec<ProverInputProof>,
    pub prover_sig: Vec<u8>,
}

/// Per-input proof from the prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverInputProof {
    pub input_global_index: u64,
    pub fcmp_proof: Vec<u8>,
    pub key_image: [u8; 32],
}

impl ProverOutput {
    /// Compute the bytes that the prover signs.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.prover_index);
        buf.extend_from_slice(&self.intent_hash);
        buf.extend_from_slice(&(self.fcmp_proofs.len() as u32).to_le_bytes());
        for proof in &self.fcmp_proofs {
            buf.extend_from_slice(&proof.input_global_index.to_le_bytes());
            buf.extend_from_slice(&(proof.fcmp_proof.len() as u32).to_le_bytes());
            buf.extend_from_slice(&proof.fcmp_proof);
            buf.extend_from_slice(&proof.key_image);
        }
        buf
    }

    /// Compute the commitment hash for equivocation detection (SS12.2.1).
    pub fn fcmp_proof_commitment(&self) -> [u8; 32] {
        shekyl_crypto_hash::cn_fast_hash(&self.signable_bytes())
    }
}

/// ProverReceipt: the prover's tiebreaker acknowledgment
/// (PQC_MULTISIG.md SS10.5, message type 0x05).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverReceipt {
    pub prover_index: u8,
    pub intent_hash: [u8; 32],
    pub local_counter: u64,
    pub receipt_sig: Vec<u8>,
}

impl ProverReceipt {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(73);
        buf.push(self.prover_index);
        buf.extend_from_slice(&self.intent_hash);
        buf.extend_from_slice(&self.local_counter.to_le_bytes());
        buf
    }
}

/// SignatureShare: a signer's hybrid signature plus commitments
/// (PQC_MULTISIG.md SS12.2.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureShare {
    pub signer_index: u8,
    pub hybrid_sig: Vec<u8>,
    pub tx_hash_commitment: [u8; 32],
    pub fcmp_proof_commitment: [u8; 32],
    pub bp_plus_proof_commitment: [u8; 32],
}

/// EquivocationProof: evidence of prover equivocation (SS12.2.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub prover_index: u8,
    pub intent_hash: [u8; 32],
    pub proof_a: ProverOutput,
    pub proof_b: ProverOutput,
}

impl EquivocationProof {
    /// Verify that proof_a and proof_b are indeed different proofs
    /// from the same prover for the same intent.
    pub fn is_valid(&self) -> bool {
        self.proof_a.prover_index == self.prover_index
            && self.proof_b.prover_index == self.prover_index
            && self.proof_a.intent_hash == self.intent_hash
            && self.proof_b.intent_hash == self.intent_hash
            && self.proof_a.fcmp_proof_commitment() != self.proof_b.fcmp_proof_commitment()
    }
}

/// InvariantViolation: signed notice of honest-signer invariant failure
/// (PQC_MULTISIG.md SS12.2.6).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub reporter_index: u8,
    pub intent_hash: [u8; 32],
    pub invariant_id: u8,
    pub evidence: Vec<u8>,
    pub reporter_sig: Vec<u8>,
}

/// Veto: refusal to sign (message type 0x04).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Veto {
    pub sender_index: u8,
    pub intent_hash: [u8; 32],
    pub reason: VetoReason,
    pub sender_sig: Vec<u8>,
}

/// Veto reasons.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VetoReason {
    InvariantFailed(u8),
    ProverEquivocation,
    ChainStateMismatch,
    RateLimitExceeded,
    Manual(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prover_output_commitment_deterministic() {
        let po = ProverOutput {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            fcmp_proofs: vec![ProverInputProof {
                input_global_index: 42,
                fcmp_proof: vec![0xBB; 100],
                key_image: [0xCC; 32],
            }],
            prover_sig: vec![0; 64],
        };
        let c1 = po.fcmp_proof_commitment();
        let c2 = po.fcmp_proof_commitment();
        assert_eq!(c1, c2);
        assert_ne!(c1, [0; 32]);
    }

    #[test]
    fn prover_output_commitment_changes_with_proof() {
        let po1 = ProverOutput {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            fcmp_proofs: vec![ProverInputProof {
                input_global_index: 42,
                fcmp_proof: vec![0xBB; 100],
                key_image: [0xCC; 32],
            }],
            prover_sig: vec![0; 64],
        };
        let mut po2 = po1.clone();
        po2.fcmp_proofs[0].fcmp_proof[0] = 0xFF;
        assert_ne!(po1.fcmp_proof_commitment(), po2.fcmp_proof_commitment());
    }

    #[test]
    fn equivocation_proof_valid() {
        let po_a = ProverOutput {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            fcmp_proofs: vec![ProverInputProof {
                input_global_index: 42,
                fcmp_proof: vec![0xBB; 100],
                key_image: [0xCC; 32],
            }],
            prover_sig: vec![0; 64],
        };
        let mut po_b = po_a.clone();
        po_b.fcmp_proofs[0].fcmp_proof[0] = 0xFF;

        let ep = EquivocationProof {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            proof_a: po_a,
            proof_b: po_b,
        };
        assert!(ep.is_valid());
    }

    #[test]
    fn equivocation_proof_rejects_identical() {
        let po = ProverOutput {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            fcmp_proofs: vec![ProverInputProof {
                input_global_index: 42,
                fcmp_proof: vec![0xBB; 100],
                key_image: [0xCC; 32],
            }],
            prover_sig: vec![0; 64],
        };

        let ep = EquivocationProof {
            prover_index: 1,
            intent_hash: [0xAA; 32],
            proof_a: po.clone(),
            proof_b: po,
        };
        assert!(!ep.is_valid());
    }

    #[test]
    fn prover_receipt_signable_bytes() {
        let pr = ProverReceipt {
            prover_index: 2,
            intent_hash: [0xDD; 32],
            local_counter: 7,
            receipt_sig: vec![0; 64],
        };
        let bytes = pr.signable_bytes();
        assert_eq!(bytes.len(), 1 + 32 + 8);
        assert_eq!(bytes[0], 2);
    }
}
