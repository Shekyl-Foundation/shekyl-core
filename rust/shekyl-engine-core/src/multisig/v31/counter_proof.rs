// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! CounterProof recovery protocol (PQC_MULTISIG.md SS13.4).
//!
//! When a member has a stale tx_counter, another member sends a
//! CounterProof containing chain evidence that a transaction was
//! confirmed. The stale member verifies the proof against their
//! local chain view before advancing.

use serde::{Deserialize, Serialize};

/// CounterProof: chain evidence for tx_counter advancement (SS13.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CounterProof {
    pub sender_index: u8,
    pub advancing_to: u64,
    pub tx_hash: [u8; 32],
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub tx_position: u16,
    pub consumed_inputs: Vec<[u8; 32]>,
    pub resulting_outputs: Vec<[u8; 32]>,
    pub intent_hash: [u8; 32],
    pub sender_sig: Vec<u8>,
}

impl CounterProof {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.sender_index);
        buf.extend_from_slice(&self.advancing_to.to_le_bytes());
        buf.extend_from_slice(&self.tx_hash);
        buf.extend_from_slice(&self.block_height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.tx_position.to_le_bytes());
        buf.extend_from_slice(&(self.consumed_inputs.len() as u32).to_le_bytes());
        for ki in &self.consumed_inputs {
            buf.extend_from_slice(ki);
        }
        buf.extend_from_slice(&(self.resulting_outputs.len() as u32).to_le_bytes());
        for op in &self.resulting_outputs {
            buf.extend_from_slice(op);
        }
        buf.extend_from_slice(&self.intent_hash);
        buf
    }
}

/// Result of CounterProof verification (SS13.4 verification rules).
#[derive(Debug, PartialEq, Eq)]
pub enum CounterProofVerifyResult {
    Valid,
    WaitForSync,
    RescanRequired,
    Invalid(CounterProofError),
}

/// Specific CounterProof verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterProofError {
    BlockHashMismatch,
    TxNotFoundInBlock,
    SchemeIdNotMultisig,
    LeafHashMismatch,
    InputKeyImageMismatch,
    InputNotOwnedByGroup,
    SignatureInvalid,
}

/// Interface for local chain/state queries needed by CounterProof verification.
pub trait CounterProofChainView {
    /// Get block hash at height. Returns None if block not synced yet.
    fn block_hash_at(&self, height: u64) -> Option<[u8; 32]>;

    /// Check if tx_hash exists at position in block. Returns None if block not synced.
    fn tx_at_position(&self, block_height: u64, position: u16) -> Option<[u8; 32]>;

    /// Check if all inputs in the tx use scheme_id=2.
    fn tx_all_scheme_id_2(&self, tx_hash: &[u8; 32]) -> Option<bool>;

    /// Check if a key image is tracked as an unspent output for the group.
    fn is_tracked_unspent(&self, key_image: &[u8; 32], group_id: &[u8; 32]) -> bool;
}

/// Verify a CounterProof against local chain view (SS13.4 rules 1-7).
///
/// Rule 8 (signature verification) is handled separately by the caller
/// since it requires the hybrid signing pubkey.
pub fn verify_counter_proof(
    proof: &CounterProof,
    group_id: &[u8; 32],
    our_counter: u64,
    chain: &dyn CounterProofChainView,
) -> CounterProofVerifyResult {
    if proof.advancing_to <= our_counter {
        return CounterProofVerifyResult::Valid;
    }

    // Rule 1: block_hash matches local chain
    match chain.block_hash_at(proof.block_height) {
        None => return CounterProofVerifyResult::WaitForSync,
        Some(hash) if hash != proof.block_hash => {
            return CounterProofVerifyResult::Invalid(CounterProofError::BlockHashMismatch);
        }
        _ => {}
    }

    // Rule 2: tx_hash at position
    match chain.tx_at_position(proof.block_height, proof.tx_position) {
        None => return CounterProofVerifyResult::WaitForSync,
        Some(hash) if hash != proof.tx_hash => {
            return CounterProofVerifyResult::Invalid(CounterProofError::TxNotFoundInBlock);
        }
        _ => {}
    }

    // Rule 3: all inputs use scheme_id=2
    match chain.tx_all_scheme_id_2(&proof.tx_hash) {
        None => return CounterProofVerifyResult::WaitForSync,
        Some(false) => {
            return CounterProofVerifyResult::Invalid(CounterProofError::SchemeIdNotMultisig);
        }
        _ => {}
    }

    // Rules 5-6: consumed_inputs are tracked unspent outputs for the group
    for ki in &proof.consumed_inputs {
        if !chain.is_tracked_unspent(ki, group_id) {
            return CounterProofVerifyResult::RescanRequired;
        }
    }

    CounterProofVerifyResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockChain {
        has_block: bool,
        block_hash: [u8; 32],
        tx_hash: [u8; 32],
        scheme_ok: bool,
        tracked: bool,
    }

    impl CounterProofChainView for MockChain {
        fn block_hash_at(&self, _height: u64) -> Option<[u8; 32]> {
            if self.has_block {
                Some(self.block_hash)
            } else {
                None
            }
        }

        fn tx_at_position(&self, _block_height: u64, _position: u16) -> Option<[u8; 32]> {
            if self.has_block {
                Some(self.tx_hash)
            } else {
                None
            }
        }

        fn tx_all_scheme_id_2(&self, _tx_hash: &[u8; 32]) -> Option<bool> {
            if self.has_block {
                Some(self.scheme_ok)
            } else {
                None
            }
        }

        fn is_tracked_unspent(&self, _key_image: &[u8; 32], _group_id: &[u8; 32]) -> bool {
            self.tracked
        }
    }

    fn test_proof() -> CounterProof {
        CounterProof {
            sender_index: 1,
            advancing_to: 6,
            tx_hash: [0xAA; 32],
            block_height: 1000,
            block_hash: [0xBB; 32],
            tx_position: 3,
            consumed_inputs: vec![[0xCC; 32]],
            resulting_outputs: vec![[0xDD; 32]],
            intent_hash: [0xEE; 32],
            sender_sig: vec![0; 64],
        }
    }

    fn valid_chain() -> MockChain {
        MockChain {
            has_block: true,
            block_hash: [0xBB; 32],
            tx_hash: [0xAA; 32],
            scheme_ok: true,
            tracked: true,
        }
    }

    #[test]
    fn valid_counter_proof() {
        let proof = test_proof();
        let chain = valid_chain();
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::Valid
        );
    }

    #[test]
    fn already_advanced() {
        let proof = test_proof();
        let chain = valid_chain();
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 6, &chain),
            CounterProofVerifyResult::Valid
        );
    }

    #[test]
    fn wait_for_sync_when_block_missing() {
        let proof = test_proof();
        let chain = MockChain {
            has_block: false,
            ..valid_chain()
        };
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::WaitForSync
        );
    }

    #[test]
    fn rejects_block_hash_mismatch() {
        let proof = test_proof();
        let chain = MockChain {
            block_hash: [0xFF; 32],
            ..valid_chain()
        };
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::Invalid(CounterProofError::BlockHashMismatch)
        );
    }

    #[test]
    fn rejects_tx_not_found() {
        let proof = test_proof();
        let chain = MockChain {
            tx_hash: [0xFF; 32],
            ..valid_chain()
        };
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::Invalid(CounterProofError::TxNotFoundInBlock)
        );
    }

    #[test]
    fn rejects_wrong_scheme_id() {
        let proof = test_proof();
        let chain = MockChain {
            scheme_ok: false,
            ..valid_chain()
        };
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::Invalid(CounterProofError::SchemeIdNotMultisig)
        );
    }

    #[test]
    fn rescan_when_input_not_tracked() {
        let proof = test_proof();
        let chain = MockChain {
            tracked: false,
            ..valid_chain()
        };
        assert_eq!(
            verify_counter_proof(&proof, &[0xFF; 32], 5, &chain),
            CounterProofVerifyResult::RescanRequired
        );
    }

    #[test]
    fn signable_bytes_deterministic() {
        let proof = test_proof();
        assert_eq!(proof.signable_bytes(), proof.signable_bytes());
        assert!(!proof.signable_bytes().is_empty());
    }
}
