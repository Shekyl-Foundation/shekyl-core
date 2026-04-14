// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! SpendIntent: the proposal message that initiates a multisig spend
//! (PQC_MULTISIG.md SS9.1–SS9.4).
//!
//! A proposer constructs a `SpendIntent`, signs it with their hybrid key,
//! and broadcasts to the group. Each verifier runs the 14-check validation
//! pipeline before proceeding to sign.

use serde::{Deserialize, Serialize};

/// Current SpendIntent version.
pub const SPEND_INTENT_VERSION: u8 = 1;

/// Maximum validity window for an intent (24 hours in seconds).
pub const MAX_VALIDITY_SECS: u64 = 86400;

/// Minimum reference block age in blocks behind tip.
pub const FCMP_REFERENCE_BLOCK_MIN_AGE: u64 = 10;

/// Maximum reference block age in blocks behind tip.
pub const FCMP_REFERENCE_BLOCK_MAX_AGE: u64 = 100;

/// Maximum recipients per intent (bounds allocation from untrusted input).
pub const MAX_RECIPIENTS: u32 = 16;

/// Maximum inputs per intent (bounds allocation from untrusted input).
pub const MAX_INPUTS: u32 = 128;

/// Maximum address byte length (bounds allocation from untrusted input).
pub const MAX_ADDRESS_LEN: u32 = 65536;

/// Errors during SpendIntent validation (SS9.2 invariant checks).
#[derive(Debug, thiserror::Error)]
pub enum SpendIntentError {
    #[error("wrong version: expected {SPEND_INTENT_VERSION}, got {0}")]
    WrongVersion(u8),

    #[error("group_id mismatch")]
    GroupIdMismatch,

    #[error("proposer_index {0} >= n_total")]
    ProposerOutOfRange(u8),

    #[error("proposer signature verification failed")]
    ProposerSigInvalid,

    #[error("intent expired: now={now}, expires_at={expires_at}")]
    Expired { now: u64, expires_at: u64 },

    #[error("intent not yet valid: now={now}, created_at={created_at}")]
    NotYetValid { now: u64, created_at: u64 },

    #[error("validity window {window}s exceeds maximum {MAX_VALIDITY_SECS}s")]
    ValidityTooLong { window: u64 },

    #[error("tx_counter mismatch: expected {expected}, got {got}")]
    CounterMismatch { expected: u64, got: u64 },

    #[error("reference_block_height {height} too fresh (tip={tip}, min_age={FCMP_REFERENCE_BLOCK_MIN_AGE})")]
    RefBlockTooFresh { height: u64, tip: u64 },

    #[error("reference_block_height {height} too stale (tip={tip}, max_age={FCMP_REFERENCE_BLOCK_MAX_AGE})")]
    RefBlockTooStale { height: u64, tip: u64 },

    #[error("reference_block_hash mismatch at height {height}")]
    RefBlockHashMismatch { height: u64 },

    #[error("input {index} not owned by group or already spent")]
    InputNotOwned { index: u64 },

    #[error("recipients not sorted or contain duplicate (address, amount) tuples")]
    RecipientsNotSorted,

    #[error("balance mismatch: inputs={inputs}, outputs+fee={outputs_plus_fee}")]
    BalanceMismatch { inputs: u64, outputs_plus_fee: u64 },

    #[error("kem_randomness_seed reused (replay detected)")]
    KemSeedReplay,

    #[error("chain_state_fingerprint mismatch")]
    ChainStateMismatch,

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// A recipient in a SpendIntent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRecipient {
    pub address: Vec<u8>,
    pub amount: u64,
}

impl PartialOrd for IntentRecipient {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IntentRecipient {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address
            .cmp(&other.address)
            .then_with(|| self.amount.cmp(&other.amount))
    }
}

/// SpendIntent: the proposal message for a multisig spend (SS9.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendIntent {
    pub version: u8,
    pub intent_id: [u8; 32],

    pub group_id: [u8; 32],

    pub proposer_index: u8,
    pub proposer_sig: Vec<u8>,

    pub created_at: u64,
    pub expires_at: u64,
    pub tx_counter: u64,
    pub reference_block_height: u64,
    pub reference_block_hash: [u8; 32],

    pub recipients: Vec<IntentRecipient>,
    pub fee: u64,
    pub input_global_indices: Vec<u64>,

    pub kem_randomness_seed: [u8; 32],
    pub chain_state_fingerprint: [u8; 32],
}

impl SpendIntent {
    /// Compute `intent_hash = cn_fast_hash(canonical_serialize(SpendIntent))` (SS9.4).
    pub fn intent_hash(&self) -> [u8; 32] {
        let canonical = self.to_canonical_bytes();
        shekyl_crypto_hash::cn_fast_hash(&canonical)
    }

    /// Canonical serialization for hashing and signing.
    ///
    /// Layout: all fixed fields in declaration order, then variable-length
    /// recipients and inputs with length prefixes (u32 LE).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.version);
        buf.extend_from_slice(&self.intent_id);
        buf.extend_from_slice(&self.group_id);
        buf.push(self.proposer_index);
        buf.extend_from_slice(&(self.proposer_sig.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.proposer_sig);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf.extend_from_slice(&self.tx_counter.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_height.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_hash);

        buf.extend_from_slice(&(self.recipients.len() as u32).to_le_bytes());
        for r in &self.recipients {
            buf.extend_from_slice(&(r.address.len() as u32).to_le_bytes());
            buf.extend_from_slice(&r.address);
            buf.extend_from_slice(&r.amount.to_le_bytes());
        }

        buf.extend_from_slice(&self.fee.to_le_bytes());

        buf.extend_from_slice(&(self.input_global_indices.len() as u32).to_le_bytes());
        for idx in &self.input_global_indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }

        buf.extend_from_slice(&self.kem_randomness_seed);
        buf.extend_from_slice(&self.chain_state_fingerprint);
        buf
    }

    /// Compute the bytes that the proposer signs (everything except proposer_sig).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.version);
        buf.extend_from_slice(&self.intent_id);
        buf.extend_from_slice(&self.group_id);
        buf.push(self.proposer_index);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf.extend_from_slice(&self.tx_counter.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_height.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_hash);

        buf.extend_from_slice(&(self.recipients.len() as u32).to_le_bytes());
        for r in &self.recipients {
            buf.extend_from_slice(&(r.address.len() as u32).to_le_bytes());
            buf.extend_from_slice(&r.address);
            buf.extend_from_slice(&r.amount.to_le_bytes());
        }

        buf.extend_from_slice(&self.fee.to_le_bytes());

        buf.extend_from_slice(&(self.input_global_indices.len() as u32).to_le_bytes());
        for idx in &self.input_global_indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }

        buf.extend_from_slice(&self.kem_randomness_seed);
        buf.extend_from_slice(&self.chain_state_fingerprint);
        buf
    }

    /// Validate structural invariants that don't require external state
    /// (checks 1, 3, 5-6, 11 from SS9.2).
    pub fn validate_structural(
        &self,
        n_total: u8,
        now_secs: u64,
    ) -> Result<(), SpendIntentError> {
        if self.version != SPEND_INTENT_VERSION {
            return Err(SpendIntentError::WrongVersion(self.version));
        }
        if self.proposer_index >= n_total {
            return Err(SpendIntentError::ProposerOutOfRange(self.proposer_index));
        }
        if now_secs < self.created_at {
            return Err(SpendIntentError::NotYetValid {
                now: now_secs,
                created_at: self.created_at,
            });
        }
        if now_secs > self.expires_at {
            return Err(SpendIntentError::Expired {
                now: now_secs,
                expires_at: self.expires_at,
            });
        }
        let window = self.expires_at.saturating_sub(self.created_at);
        if window > MAX_VALIDITY_SECS {
            return Err(SpendIntentError::ValidityTooLong { window });
        }

        let mut sorted = self.recipients.clone();
        sorted.sort();
        if sorted != self.recipients {
            return Err(SpendIntentError::RecipientsNotSorted);
        }
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(SpendIntentError::RecipientsNotSorted);
            }
        }

        Ok(())
    }

    /// Validate temporal binding against local chain view (checks 7-9 from SS9.2).
    pub fn validate_temporal(
        &self,
        expected_counter: u64,
        chain_tip_height: u64,
        local_block_hash_at_ref_height: &[u8; 32],
    ) -> Result<(), SpendIntentError> {
        if self.tx_counter != expected_counter {
            return Err(SpendIntentError::CounterMismatch {
                expected: expected_counter,
                got: self.tx_counter,
            });
        }

        if chain_tip_height
            .checked_sub(self.reference_block_height)
            .map_or(true, |age| age < FCMP_REFERENCE_BLOCK_MIN_AGE)
        {
            return Err(SpendIntentError::RefBlockTooFresh {
                height: self.reference_block_height,
                tip: chain_tip_height,
            });
        }

        if chain_tip_height
            .checked_sub(self.reference_block_height)
            .map_or(true, |age| age > FCMP_REFERENCE_BLOCK_MAX_AGE)
        {
            return Err(SpendIntentError::RefBlockTooStale {
                height: self.reference_block_height,
                tip: chain_tip_height,
            });
        }

        if self.reference_block_hash != *local_block_hash_at_ref_height {
            return Err(SpendIntentError::RefBlockHashMismatch {
                height: self.reference_block_height,
            });
        }

        Ok(())
    }

    /// Validate chain state fingerprint (check 14 from SS9.2, invariant I2).
    pub fn validate_chain_state(
        &self,
        local_fingerprint: &ChainStateFingerprint,
    ) -> Result<(), SpendIntentError> {
        let expected = local_fingerprint.compute();
        if self.chain_state_fingerprint != expected {
            return Err(SpendIntentError::ChainStateMismatch);
        }
        Ok(())
    }

    /// Validate balance (check 12 from SS9.2).
    pub fn validate_balance(&self, input_amounts: &[u64]) -> Result<(), SpendIntentError> {
        let inputs_sum: u64 = input_amounts
            .iter()
            .copied()
            .try_fold(0u64, |acc, x| acc.checked_add(x))
            .ok_or_else(|| SpendIntentError::Serialization("input amounts overflow u64".into()))?;
        let outputs_sum: u64 = self
            .recipients
            .iter()
            .map(|r| r.amount)
            .try_fold(0u64, |acc, x| acc.checked_add(x))
            .ok_or_else(|| {
                SpendIntentError::Serialization("output amounts overflow u64".into())
            })?;
        let outputs_plus_fee = outputs_sum.checked_add(self.fee).ok_or_else(|| {
            SpendIntentError::Serialization("outputs + fee overflow u64".into())
        })?;
        if inputs_sum != outputs_plus_fee {
            return Err(SpendIntentError::BalanceMismatch {
                inputs: inputs_sum,
                outputs_plus_fee,
            });
        }
        Ok(())
    }
}

/// Chain state fingerprint computation (SS9.3).
///
/// Members must agree on chain state before signing. Constructed from
/// the proposer's or verifier's local view, then compared.
pub struct ChainStateFingerprint {
    pub reference_block_hash: [u8; 32],
    pub input_global_indices: Vec<u64>,
    pub input_eligible_heights: Vec<u64>,
    pub input_amounts: Vec<u64>,
    pub input_assigned_prover_indices: Vec<u8>,
}

impl ChainStateFingerprint {
    /// Compute the 32-byte fingerprint per SS9.3.
    pub fn compute(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.reference_block_hash);

        let mut sorted_indices = self.input_global_indices.clone();
        sorted_indices.sort();
        for idx in &sorted_indices {
            preimage.extend_from_slice(&idx.to_le_bytes());
        }

        let mut sorted_heights = self.input_eligible_heights.clone();
        sorted_heights.sort();
        for h in &sorted_heights {
            preimage.extend_from_slice(&h.to_le_bytes());
        }

        let mut sorted_amounts = self.input_amounts.clone();
        sorted_amounts.sort();
        for a in &sorted_amounts {
            preimage.extend_from_slice(&a.to_le_bytes());
        }

        let mut sorted_provers = self.input_assigned_prover_indices.clone();
        sorted_provers.sort();
        for p in &sorted_provers {
            preimage.push(*p);
        }

        shekyl_crypto_hash::cn_fast_hash(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_intent() -> SpendIntent {
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
            recipients: vec![
                IntentRecipient {
                    address: vec![1, 2, 3],
                    amount: 100,
                },
                IntentRecipient {
                    address: vec![4, 5, 6],
                    amount: 200,
                },
            ],
            fee: 10,
            input_global_indices: vec![42, 99],
            kem_randomness_seed: [0xDD; 32],
            chain_state_fingerprint: [0; 32],
        }
    }

    #[test]
    fn intent_hash_deterministic() {
        let intent = make_test_intent();
        let h1 = intent.intent_hash();
        let h2 = intent.intent_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0; 32]);
    }

    #[test]
    fn intent_hash_changes_with_content() {
        let i1 = make_test_intent();
        let mut i2 = make_test_intent();
        i2.fee = 20;
        assert_ne!(i1.intent_hash(), i2.intent_hash());
    }

    #[test]
    fn canonical_bytes_roundtrip_length() {
        let intent = make_test_intent();
        let bytes = intent.to_canonical_bytes();
        assert!(bytes.len() > 200);
    }

    #[test]
    fn validate_structural_passes() {
        let intent = make_test_intent();
        intent.validate_structural(3, 1500).unwrap();
    }

    #[test]
    fn validate_structural_rejects_wrong_version() {
        let mut intent = make_test_intent();
        intent.version = 2;
        assert!(matches!(
            intent.validate_structural(3, 1500),
            Err(SpendIntentError::WrongVersion(2))
        ));
    }

    #[test]
    fn validate_structural_rejects_proposer_out_of_range() {
        let mut intent = make_test_intent();
        intent.proposer_index = 5;
        assert!(matches!(
            intent.validate_structural(3, 1500),
            Err(SpendIntentError::ProposerOutOfRange(5))
        ));
    }

    #[test]
    fn validate_structural_rejects_expired() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_structural(3, 3000),
            Err(SpendIntentError::Expired { .. })
        ));
    }

    #[test]
    fn validate_structural_rejects_not_yet_valid() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_structural(3, 500),
            Err(SpendIntentError::NotYetValid { .. })
        ));
    }

    #[test]
    fn validate_structural_rejects_too_long_window() {
        let mut intent = make_test_intent();
        intent.expires_at = intent.created_at + MAX_VALIDITY_SECS + 1;
        assert!(matches!(
            intent.validate_structural(3, intent.created_at + 1),
            Err(SpendIntentError::ValidityTooLong { .. })
        ));
    }

    #[test]
    fn validate_structural_rejects_unsorted_recipients() {
        let mut intent = make_test_intent();
        intent.recipients.reverse();
        assert!(matches!(
            intent.validate_structural(3, 1500),
            Err(SpendIntentError::RecipientsNotSorted)
        ));
    }

    #[test]
    fn validate_structural_rejects_duplicate_recipients() {
        let mut intent = make_test_intent();
        intent.recipients.push(intent.recipients[0].clone());
        intent.recipients.sort();
        assert!(matches!(
            intent.validate_structural(3, 1500),
            Err(SpendIntentError::RecipientsNotSorted)
        ));
    }

    #[test]
    fn validate_temporal_passes() {
        let intent = make_test_intent();
        intent
            .validate_temporal(5, 950, &[0xCC; 32])
            .unwrap();
    }

    #[test]
    fn validate_temporal_rejects_counter_mismatch() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_temporal(6, 950, &[0xCC; 32]),
            Err(SpendIntentError::CounterMismatch { expected: 6, got: 5 })
        ));
    }

    #[test]
    fn validate_temporal_rejects_ref_block_too_fresh() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_temporal(5, 905, &[0xCC; 32]),
            Err(SpendIntentError::RefBlockTooFresh { .. })
        ));
    }

    #[test]
    fn validate_temporal_rejects_ref_block_too_stale() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_temporal(5, 1100, &[0xCC; 32]),
            Err(SpendIntentError::RefBlockTooStale { .. })
        ));
    }

    #[test]
    fn validate_temporal_rejects_ref_block_hash_mismatch() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_temporal(5, 950, &[0xFF; 32]),
            Err(SpendIntentError::RefBlockHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_balance_passes() {
        let intent = make_test_intent();
        intent.validate_balance(&[210, 100]).unwrap();
    }

    #[test]
    fn validate_balance_rejects_mismatch() {
        let intent = make_test_intent();
        assert!(matches!(
            intent.validate_balance(&[100, 100]),
            Err(SpendIntentError::BalanceMismatch { .. })
        ));
    }

    #[test]
    fn chain_state_fingerprint_deterministic() {
        let fp = ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![42, 99],
            input_eligible_heights: vec![800, 850],
            input_amounts: vec![100, 200],
            input_assigned_prover_indices: vec![0, 1],
        };
        let h1 = fp.compute();
        let h2 = fp.compute();
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_state_fingerprint_changes_with_prover() {
        let fp1 = ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![100],
            input_assigned_prover_indices: vec![0],
        };
        let fp2 = ChainStateFingerprint {
            input_assigned_prover_indices: vec![1],
            ..ChainStateFingerprint {
                reference_block_hash: fp1.reference_block_hash,
                input_global_indices: fp1.input_global_indices.clone(),
                input_eligible_heights: fp1.input_eligible_heights.clone(),
                input_amounts: fp1.input_amounts.clone(),
                input_assigned_prover_indices: vec![1],
            }
        };
        assert_ne!(fp1.compute(), fp2.compute());
    }
}
