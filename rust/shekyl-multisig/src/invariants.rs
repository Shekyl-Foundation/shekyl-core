// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! The intent a member may sign: [`ValidatedIntent`] (`PQC_MULTISIG.md`
//! §2.7, §9.2, §9.3).
//!
//! A member signs only for an intent that is valid against its own view of
//! the chain and its own ledger: I1 (the intent's structure, its group, its
//! reference block, its balance and its seed's freshness) and I2 (the chain
//! state fingerprint). Both run once, in [`ValidatedIntent::validate`],
//! which is the type's only constructor. The ceremony takes a
//! `ValidatedIntent`, never a `SpendIntent`, so a member cannot be led into
//! a signing step over an intent it has not checked.
//!
//! The other honest-signer checks are types too, in the ceremony: a proof
//! verifies once and becomes a verified type, and the transaction a member
//! signs is one it assembled itself from its context and those verified
//! proofs (`crate::ceremony`).

use std::collections::HashSet;

use shekyl_units::AtomicUnits;

use crate::intent::{SpendIntent, SpendIntentError};

/// What a member's own wallet knows that an intent is checked against.
pub struct LedgerView<'a> {
    /// This member's group, by its address fingerprint.
    pub our_address_fingerprint: &'a [u8; 32],
    /// The group's member count.
    pub n_total: u8,
    /// The group's threshold.
    pub m_required: u8,
    /// This member's chain tip height.
    pub chain_tip_height: u64,
    /// The block hash at the intent's reference height, in this member's
    /// chain.
    pub local_ref_block_hash: &'a [u8; 32],
    /// The chain state fingerprint this member computes over the intent's
    /// inputs.
    pub local_chain_state_fingerprint: &'a [u8; 32],
    /// The amounts of the intent's inputs, in this member's ledger.
    pub input_amounts: &'a [AtomicUnits],
    /// Every `kem_randomness_seed` this member has seen in an intent.
    pub seen_kem_seeds: &'a HashSet<[u8; 32]>,
}

/// Why a member will not sign an intent. Each names one check.
#[derive(Debug, thiserror::Error)]
pub enum IntentRefusal {
    /// I1: the intent is for another group.
    #[error("the intent is for another group")]
    OtherGroup,
    /// I1: the intent's structure (§9.2 items 1–4, 9, 10).
    #[error("the intent is malformed: {0}")]
    Structure(SpendIntentError),
    /// I1: the reference block (§9.2 items 7–8).
    #[error("the intent's reference block does not hold here: {0}")]
    ReferenceBlock(SpendIntentError),
    /// I1: the amounts do not balance (§9.2 item 11).
    #[error("the intent does not balance: {0}")]
    Balance(SpendIntentError),
    /// I1: the seed was used before (§9.2 item 12).
    #[error("the intent's kem_randomness_seed was seen before")]
    KemSeedReplay,
    /// I2: this member's chain state differs (§9.3).
    #[error("the chain state fingerprint differs from this member's")]
    ChainState,
}

/// An intent that passed I1 and I2 against one member's ledger.
#[derive(Debug, Clone)]
pub struct ValidatedIntent {
    intent: SpendIntent,
    hash: [u8; 32],
}

impl ValidatedIntent {
    /// Check `intent` against `ledger`: I1 then I2.
    ///
    /// # Errors
    ///
    /// The first [`IntentRefusal`] that holds.
    pub fn validate(intent: SpendIntent, ledger: &LedgerView<'_>) -> Result<Self, IntentRefusal> {
        if intent.address_fingerprint != *ledger.our_address_fingerprint {
            return Err(IntentRefusal::OtherGroup);
        }
        intent
            .validate_structural(ledger.n_total, ledger.m_required)
            .map_err(IntentRefusal::Structure)?;
        intent
            .validate_temporal(ledger.chain_tip_height, ledger.local_ref_block_hash)
            .map_err(IntentRefusal::ReferenceBlock)?;
        intent
            .validate_balance(ledger.input_amounts)
            .map_err(IntentRefusal::Balance)?;
        if ledger.seen_kem_seeds.contains(&intent.kem_randomness_seed) {
            return Err(IntentRefusal::KemSeedReplay);
        }
        if intent.chain_state_fingerprint != *ledger.local_chain_state_fingerprint {
            return Err(IntentRefusal::ChainState);
        }
        let hash = intent.intent_hash().map_err(IntentRefusal::Structure)?;
        Ok(Self { intent, hash })
    }

    /// The intent.
    #[must_use]
    pub fn intent(&self) -> &SpendIntent {
        &self.intent
    }

    /// Its hash, which every file of its ceremony carries.
    #[must_use]
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{ChainStateFingerprint, IntentRecipient, SPEND_INTENT_VERSION};

    fn chain_fingerprint() -> [u8; 32] {
        ChainStateFingerprint {
            reference_block_hash: [0xCC; 32],
            input_global_indices: vec![42],
            input_eligible_heights: vec![800],
            input_amounts: vec![AtomicUnits::from_raw(310)],
        }
        .compute()
    }

    fn intent() -> SpendIntent {
        SpendIntent {
            version: SPEND_INTENT_VERSION,
            intent_id: [0xAA; 32],
            address_fingerprint: [0xBB; 32],
            proposer_index: 0,
            signers: vec![0, 2],
            responder_index: 2,
            created_at: 1000,
            reference_block_height: 900,
            reference_block_hash: [0xCC; 32],
            recipients: vec![IntentRecipient {
                address: vec![1, 2, 3],
                amount: AtomicUnits::from_raw(300),
            }],
            fee: AtomicUnits::from_raw(10),
            input_global_indices: vec![42],
            kem_randomness_seed: [0xDD; 32],
            chain_state_fingerprint: chain_fingerprint(),
        }
    }

    fn check(
        intent: SpendIntent,
        seen: &HashSet<[u8; 32]>,
    ) -> Result<ValidatedIntent, IntentRefusal> {
        ValidatedIntent::validate(
            intent,
            &LedgerView {
                our_address_fingerprint: &[0xBB; 32],
                n_total: 3,
                m_required: 2,
                chain_tip_height: 950,
                local_ref_block_hash: &[0xCC; 32],
                local_chain_state_fingerprint: &chain_fingerprint(),
                input_amounts: &[AtomicUnits::from_raw(310)],
                seen_kem_seeds: seen,
            },
        )
    }

    #[test]
    fn a_valid_intent_validates_and_carries_its_hash() {
        let validated = check(intent(), &HashSet::new()).unwrap();
        assert_eq!(*validated.hash(), intent().intent_hash().unwrap());
    }

    /// Each refusal by name.
    #[test]
    fn each_check_refuses_by_name() {
        let seen = HashSet::new();
        let refused = |edit: &dyn Fn(&mut SpendIntent)| {
            let mut i = intent();
            edit(&mut i);
            check(i, &seen).err()
        };
        assert!(matches!(
            refused(&|i| i.address_fingerprint = [0xBC; 32]),
            Some(IntentRefusal::OtherGroup)
        ));
        assert!(matches!(
            refused(&|i| i.signers = vec![0]),
            Some(IntentRefusal::Structure(_))
        ));
        assert!(matches!(
            refused(&|i| i.reference_block_hash = [0xCD; 32]),
            Some(IntentRefusal::ReferenceBlock(_))
        ));
        assert!(matches!(
            refused(&|i| i.fee = AtomicUnits::from_raw(11)),
            Some(IntentRefusal::Balance(_))
        ));
        assert!(matches!(
            refused(&|i| i.chain_state_fingerprint = [0; 32]),
            Some(IntentRefusal::ChainState)
        ));
        let seen = HashSet::from([[0xDD; 32]]);
        assert!(matches!(
            check(intent(), &seen).err(),
            Some(IntentRefusal::KemSeedReplay)
        ));
    }
}
