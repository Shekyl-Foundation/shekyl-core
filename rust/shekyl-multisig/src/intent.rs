// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! SpendIntent: the proposal that starts a multisig spend
//! (`PQC_MULTISIG.md` §9.1–§9.4).
//!
//! **The intent is the only input a signer trusts** (R-7). A proposer writes
//! it, signs the `Proposal` file that carries it with its envelope key
//! (`shekyl_crypto_pq::multisig_envelope`, R-6), and every signer rebuilds
//! every signing input from it alone: the recipients and fee, the inputs, the
//! reference block, the signer set and the responder (R-5), and
//! `kem_randomness_seed`, the root from which the outputs, the commitment
//! blinds, the pseudo-out blinds and each input's rerandomization are
//! derived (one registered label per derived value, `PQC_MULTISIG.md` §9.5).
//! Nothing another member sends later can change what a signer signs.
//!
//! **The deadline is the reference block** (R-13). An intent expires when no
//! block can list a spend anchored at its reference block any more, measured
//! as consensus measures it (`shekyl_curve_tree::reference`, CEN-I11). There
//! is no wall-clock expiry: devices in one session do not agree to the
//! second, and a device kept in a safe may have a wrong clock. `created_at`
//! is shown to people and checked against nothing.

use serde::{Deserialize, Serialize};
use shekyl_address::multisig_address::MIN_MULTISIG_THRESHOLD;
use shekyl_curve_tree::reference;
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

/// Current SpendIntent version. Version 2 adds the signer set and the
/// responder (R-5) and drops the proposer signature and the wall-clock
/// expiry (R-6, R-13). Pre-genesis, so version 1 is refused, not migrated.
pub const SPEND_INTENT_VERSION: u8 = 2;

// `CT_TYPE_FCMP_PLUS_PLUS_PQC` comes from the JSON authority at
// `config/consensus_constants.json` (`build.rs`). The canonical wire ct-type
// `shekyl_wire::transaction::CT_TYPE_FCMP` is pinned to it by the runtime
// tripwire `wire_ct_type_matches_consensus_authority` below, and the
// generated value itself is pinned to the genesis dense baseline (`1`) by the
// const-evaluated `assert!` below. The reference-block window is not here:
// `shekyl_curve_tree::reference` owns it and is pinned against CEN-I11.
include!(concat!(
    env!("OUT_DIR"),
    "/consensus_constants_generated.rs"
));

const _: () = assert!(
    CT_TYPE_FCMP_PLUS_PLUS_PQC == 1,
    "CT_TYPE_FCMP_PLUS_PLUS_PQC diverged from the genesis dense baseline (1, GENESIS_TX_WIRE_FORMAT.md §2.0); changing the wire type number is a consensus rule change"
);

/// Maximum recipients per intent: the consensus cap on a transaction's
/// outputs (`shekyl_wire::transaction::MAX_OUTPUTS`). A change payment is a
/// recipient, the group's own address, so an intent lists every output the
/// transaction will carry. Pinned by `max_recipients_is_the_output_cap`
/// ([`SpendIntent::validate_structural`] enforces it).
pub const MAX_RECIPIENTS: u32 = 16;

/// Maximum inputs per intent: the consensus cap on a transaction's key-image
/// inputs (`shekyl_wire::transaction::MAX_FCMP_INPUTS`, CEN-I4), so an
/// intent no transaction can carry is refused before anyone signs. Pinned to
/// that constant by `max_inputs_is_the_consensus_cap` below
/// ([`SpendIntent::validate_structural`] enforces it).
pub const MAX_INPUTS: u32 = 8;

/// Maximum address byte length ([`SpendIntent::validate_structural`]).
pub const MAX_ADDRESS_LEN: u32 = 65536;

/// Errors during SpendIntent validation (SS9.2 invariant checks).
#[derive(Debug, thiserror::Error)]
pub enum SpendIntentError {
    #[error("wrong version: expected {SPEND_INTENT_VERSION}, got {0}")]
    WrongVersion(u8),

    #[error("field '{0}' too long to serialize (length exceeds u32 wire prefix)")]
    FieldTooLong(&'static str),

    #[error("address_fingerprint mismatch")]
    AddressFingerprintMismatch,

    #[error("no {m}-of-{n} multisig group exists (a group needs 2..=n signers)")]
    GroupShape { n: u8, m: u8 },

    #[error("proposer_index {0} >= n_total")]
    ProposerOutOfRange(u8),

    #[error("the intent names {got} signers; the group signs with {expected}")]
    SignerCount { expected: u8, got: usize },

    #[error("the signer indices are not strictly ascending")]
    SignersNotAscending,

    #[error("signer index {0} >= n_total")]
    SignerOutOfRange(u8),

    #[error("the proposer is not one of the signers")]
    ProposerNotSigner,

    #[error("the responder is not one of the signers")]
    ResponderNotSigner,

    #[error("the responder is the proposer")]
    ResponderIsProposer,

    #[error("reference block {height} is not yet usable at tip {tip}")]
    RefBlockTooFresh { height: u64, tip: u64 },

    #[error("reference block {height} has aged out at tip {tip}: the intent has expired")]
    RefBlockTooStale { height: u64, tip: u64 },

    #[error("reference_block_hash mismatch at height {height}")]
    RefBlockHashMismatch { height: u64 },

    #[error("input {index} not owned by group or already spent")]
    InputNotOwned { index: u64 },

    #[error("recipients not sorted or contain duplicate (address, amount) tuples")]
    RecipientsNotSorted,

    #[error("{0} inputs; an intent spends 1..={MAX_INPUTS}")]
    InputCount(usize),

    #[error("{0} recipients; an intent pays at most {MAX_RECIPIENTS}")]
    RecipientCount(usize),

    #[error("a recipient address of {0} bytes exceeds {MAX_ADDRESS_LEN}")]
    AddressTooLong(usize),

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
    pub amount: AtomicUnits,
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

    /// The group's identity, signed into the canonical bytes and enforced by
    /// invariant I1. This is the address fingerprint —
    /// `shekyl_address::address_fingerprint` over the group's
    /// `MultisigAddressPayload` — computed by the wallet and passed in; this
    /// crate carries and enforces agreement on it but does not compute it (it
    /// holds no address dependency). It replaces the former `group_id`, an
    /// identity nothing produced: the wallet enforces that the value corresponds
    /// to the address, the ceremony enforces that all participants agree on it.
    pub address_fingerprint: [u8; 32],

    /// The member who proposed the spend. Its `Proposal` file's envelope
    /// signature is the proposal's signature, and the file's sender index
    /// must equal this field.
    pub proposer_index: u8,
    /// The `m` members who will sign, strictly ascending, the proposer among
    /// them (R-5). In the intent hash, so every file of the ceremony binds it.
    pub signers: Vec<u8>,
    /// The ephemeral responder (R-2): one of `signers`, not the proposer.
    pub responder_index: u8,

    /// Unix seconds when the proposer wrote the intent. Shown to people;
    /// validated against nothing (R-13).
    pub created_at: u64,
    pub reference_block_height: u64,
    pub reference_block_hash: [u8; 32],

    pub recipients: Vec<IntentRecipient>,
    pub fee: AtomicUnits,
    pub input_global_indices: Vec<u64>,

    pub kem_randomness_seed: [u8; 32],
    pub chain_state_fingerprint: [u8; 32],
}

impl SpendIntent {
    /// Compute `intent_hash = shekyl_crypto_hash::keccak256(canonical_serialize(SpendIntent))` (SS9.4).
    ///
    /// Fallible because canonical serialization is: a field whose length
    /// exceeds the u32 wire prefix has no well-defined canonical encoding
    /// (silently truncating the prefix would collide distinct intents), so
    /// it has no well-defined hash-identity either. `validate_structural`
    /// bounds every length well below `u32::MAX`, so this only fires on an
    /// unvalidated, pathologically-large intent.
    pub fn intent_hash(&self) -> Result<[u8; 32], SpendIntentError> {
        let canonical = self.to_canonical_bytes()?;
        Ok(shekyl_crypto_hash::keccak256(&canonical))
    }

    /// Append a `u32`-LE length taken from `len`, failing with
    /// `FieldTooLong(field)` if it overflows the u32 wire prefix.
    fn push_u32_len(
        buf: &mut Vec<u8>,
        len: usize,
        field: &'static str,
    ) -> Result<(), SpendIntentError> {
        let n = u32::try_from(len).map_err(|_| SpendIntentError::FieldTooLong(field))?;
        buf.extend_from_slice(&n.to_le_bytes());
        Ok(())
    }

    /// Append a `u32`-LE length prefix followed by `bytes` (see `push_u32_len`).
    fn push_len_prefixed(
        buf: &mut Vec<u8>,
        bytes: &[u8],
        field: &'static str,
    ) -> Result<(), SpendIntentError> {
        Self::push_u32_len(buf, bytes.len(), field)?;
        buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Canonical serialization for hashing (version 2):
    ///
    /// ```text
    /// version(1) ‖ intent_id(32) ‖ address_fingerprint(32) ‖ proposer_index(1) ‖
    /// u32(len) ‖ signers ‖ responder_index(1) ‖ created_at(8) ‖
    /// reference_block_height(8) ‖ reference_block_hash(32) ‖
    /// u32(count) ‖ { u32(len) ‖ address ‖ amount(8) }* ‖ fee(8) ‖
    /// u32(count) ‖ input_global_index(8)* ‖ kem_randomness_seed(32) ‖
    /// chain_state_fingerprint(32)
    /// ```
    ///
    /// Integers are little-endian. Fails with `FieldTooLong` rather than
    /// truncating a length that overflows the u32 prefix.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SpendIntentError> {
        let mut buf = Vec::with_capacity(256);
        buf.push(self.version);
        buf.extend_from_slice(&self.intent_id);
        buf.extend_from_slice(&self.address_fingerprint);
        buf.push(self.proposer_index);
        Self::push_len_prefixed(&mut buf, &self.signers, "signers")?;
        buf.push(self.responder_index);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_height.to_le_bytes());
        buf.extend_from_slice(&self.reference_block_hash);

        Self::push_u32_len(&mut buf, self.recipients.len(), "recipients")?;
        for r in &self.recipients {
            Self::push_len_prefixed(&mut buf, &r.address, "recipient address")?;
            buf.extend_from_slice(&r.amount.to_raw().to_le_bytes());
        }

        buf.extend_from_slice(&self.fee.to_raw().to_le_bytes());

        Self::push_u32_len(
            &mut buf,
            self.input_global_indices.len(),
            "input_global_indices",
        )?;
        for idx in &self.input_global_indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }

        buf.extend_from_slice(&self.kem_randomness_seed);
        buf.extend_from_slice(&self.chain_state_fingerprint);
        Ok(buf)
    }

    /// Validate the invariants that need no chain view (checks 1, 3, 5-6, 11
    /// of §9.2) for an `m_required`-of-`n_total` group: the version, the
    /// group shape (R-11), the proposer, the signer set and the responder
    /// (R-5), the size bounds [`MAX_INPUTS`], [`MAX_RECIPIENTS`] and
    /// [`MAX_ADDRESS_LEN`], and the recipients' order. Nothing here reads a
    /// clock (R-13).
    pub fn validate_structural(&self, n_total: u8, m_required: u8) -> Result<(), SpendIntentError> {
        if self.version != SPEND_INTENT_VERSION {
            return Err(SpendIntentError::WrongVersion(self.version));
        }
        if m_required < MIN_MULTISIG_THRESHOLD || m_required > n_total {
            return Err(SpendIntentError::GroupShape {
                n: n_total,
                m: m_required,
            });
        }
        if self.proposer_index >= n_total {
            return Err(SpendIntentError::ProposerOutOfRange(self.proposer_index));
        }
        if self.signers.len() != usize::from(m_required) {
            return Err(SpendIntentError::SignerCount {
                expected: m_required,
                got: self.signers.len(),
            });
        }
        if self.signers.windows(2).any(|w| w[0] >= w[1]) {
            return Err(SpendIntentError::SignersNotAscending);
        }
        if let Some(&out) = self.signers.iter().find(|&&i| i >= n_total) {
            return Err(SpendIntentError::SignerOutOfRange(out));
        }
        if !self.signers.contains(&self.proposer_index) {
            return Err(SpendIntentError::ProposerNotSigner);
        }
        if !self.signers.contains(&self.responder_index) {
            return Err(SpendIntentError::ResponderNotSigner);
        }
        if self.responder_index == self.proposer_index {
            return Err(SpendIntentError::ResponderIsProposer);
        }
        let inputs = self.input_global_indices.len();
        if inputs == 0 || inputs > MAX_INPUTS as usize {
            return Err(SpendIntentError::InputCount(inputs));
        }
        if self.recipients.len() > MAX_RECIPIENTS as usize {
            return Err(SpendIntentError::RecipientCount(self.recipients.len()));
        }
        if let Some(long) = self
            .recipients
            .iter()
            .map(|r| r.address.len())
            .find(|&len| len > MAX_ADDRESS_LEN as usize)
        {
            return Err(SpendIntentError::AddressTooLong(long));
        }

        if self.recipients.windows(2).any(|w| w[0] >= w[1]) {
            return Err(SpendIntentError::RecipientsNotSorted);
        }

        Ok(())
    }

    /// Validate the intent against this member's chain view (§9.2 items 6
    /// and 7): whether a spend anchored at the reference block can still be
    /// listed, and the reference block's hash.
    ///
    /// The window is consensus's, measured from the height the next block
    /// connects at (`shekyl_curve_tree::reference::{proof_submittable,
    /// proof_expired}`, pinned against CEN-I11). Its end is the intent's
    /// deadline (R-13): the last block that can list the spend is
    /// `reference_block_height + MAX_AGE`, so the last tip at which a signer
    /// can still submit is one below it. A reference above this member's
    /// tip has no connecting age, so it is neither expired nor submittable:
    /// the member's node is behind, and catching up clears it.
    pub fn validate_temporal(
        &self,
        chain_tip_height: u64,
        local_block_hash_at_ref_height: &[u8; 32],
    ) -> Result<(), SpendIntentError> {
        let tip = BlockHeight::from_raw(chain_tip_height);
        let reference = BlockHeight::from_raw(self.reference_block_height);
        if reference::proof_expired(tip, reference) {
            return Err(SpendIntentError::RefBlockTooStale {
                height: self.reference_block_height,
                tip: chain_tip_height,
            });
        }
        if !reference::proof_submittable(tip, reference) {
            return Err(SpendIntentError::RefBlockTooFresh {
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
    pub fn validate_balance(&self, input_amounts: &[AtomicUnits]) -> Result<(), SpendIntentError> {
        let inputs_sum = AtomicUnits::checked_sum(input_amounts.iter().copied())
            .ok_or_else(|| SpendIntentError::Serialization("input amounts overflow u64".into()))?;
        let outputs_sum = AtomicUnits::checked_sum(self.recipients.iter().map(|r| r.amount))
            .ok_or_else(|| SpendIntentError::Serialization("output amounts overflow u64".into()))?;
        let outputs_plus_fee = outputs_sum
            .checked_add(self.fee)
            .ok_or_else(|| SpendIntentError::Serialization("outputs + fee overflow u64".into()))?;
        if inputs_sum != outputs_plus_fee {
            return Err(SpendIntentError::BalanceMismatch {
                inputs: inputs_sum.to_raw(),
                outputs_plus_fee: outputs_plus_fee.to_raw(),
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
    pub input_amounts: Vec<AtomicUnits>,
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
            preimage.extend_from_slice(&a.to_raw().to_le_bytes());
        }

        shekyl_crypto_hash::keccak256(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2-of-3 intent: member 0 proposes, members 0 and 2 sign, member 2
    /// responds. Reference block 900.
    fn make_test_intent() -> SpendIntent {
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
            recipients: vec![
                IntentRecipient {
                    address: vec![1, 2, 3],
                    amount: AtomicUnits::from_raw(100),
                },
                IntentRecipient {
                    address: vec![4, 5, 6],
                    amount: AtomicUnits::from_raw(200),
                },
            ],
            fee: AtomicUnits::from_raw(10),
            input_global_indices: vec![42, 99],
            kem_randomness_seed: [0xDD; 32],
            chain_state_fingerprint: [0; 32],
        }
    }

    #[test]
    fn intent_hash_deterministic() {
        let intent = make_test_intent();
        let h1 = intent.intent_hash().unwrap();
        let h2 = intent.intent_hash().unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0; 32]);
    }

    /// The signer set and the responder are in the hash, so every file of
    /// the ceremony binds them (R-5); so is every other field.
    #[test]
    fn intent_hash_binds_the_signer_set_and_the_responder() {
        let base = make_test_intent().intent_hash().unwrap();
        let edits: [&dyn Fn(&mut SpendIntent); 4] = [
            &|i| i.fee = AtomicUnits::from_raw(20),
            &|i| i.signers = vec![0, 1],
            &|i| i.responder_index = 1,
            &|i| i.created_at = 1001,
        ];
        for edit in edits {
            let mut intent = make_test_intent();
            edit(&mut intent);
            assert_ne!(intent.intent_hash().unwrap(), base);
        }
    }

    #[test]
    fn validate_structural_passes() {
        make_test_intent().validate_structural(3, 2).unwrap();
    }

    /// Every structural refusal, by name. Nothing here reads a clock: an
    /// intent written years ago with a far-off `created_at` still passes
    /// (R-13).
    #[test]
    fn validate_structural_refuses_each_defect_by_name() {
        let refused = |n: u8, m: u8, edit: &dyn Fn(&mut SpendIntent)| {
            let mut intent = make_test_intent();
            edit(&mut intent);
            intent.validate_structural(n, m).err()
        };
        let keep = |_: &mut SpendIntent| {};
        assert!(matches!(
            refused(3, 2, &|i| i.version = 1),
            Some(SpendIntentError::WrongVersion(1))
        ));
        // R-11: a 1-of-N group, and a threshold above n.
        assert!(matches!(
            refused(3, 1, &keep),
            Some(SpendIntentError::GroupShape { n: 3, m: 1 })
        ));
        assert!(matches!(
            refused(3, 4, &keep),
            Some(SpendIntentError::GroupShape { n: 3, m: 4 })
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.proposer_index = 5),
            Some(SpendIntentError::ProposerOutOfRange(5))
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.signers = vec![0, 1, 2]),
            Some(SpendIntentError::SignerCount {
                expected: 2,
                got: 3
            })
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.signers = vec![2, 0]),
            Some(SpendIntentError::SignersNotAscending)
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.signers = vec![2, 2]),
            Some(SpendIntentError::SignersNotAscending)
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.signers = vec![0, 3]),
            Some(SpendIntentError::SignerOutOfRange(3))
        ));
        assert!(matches!(
            refused(3, 2, &|i| {
                i.signers = vec![1, 2];
            }),
            Some(SpendIntentError::ProposerNotSigner)
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.responder_index = 1),
            Some(SpendIntentError::ResponderNotSigner)
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.responder_index = 0),
            Some(SpendIntentError::ResponderIsProposer)
        ));
        assert!(matches!(
            refused(3, 2, &|i| i.recipients.reverse()),
            Some(SpendIntentError::RecipientsNotSorted)
        ));
        assert!(matches!(
            refused(3, 2, &|i| {
                i.recipients.push(i.recipients[0].clone());
                i.recipients.sort();
            }),
            Some(SpendIntentError::RecipientsNotSorted)
        ));
        assert!(refused(3, 2, &|i| i.created_at = u64::MAX).is_none());
    }

    #[test]
    fn validate_structural_refuses_each_size_bound_by_name() {
        let refused = |edit: &dyn Fn(&mut SpendIntent)| {
            let mut intent = make_test_intent();
            edit(&mut intent);
            intent.validate_structural(3, 2).err()
        };
        assert!(matches!(
            refused(&|i| i.input_global_indices.clear()),
            Some(SpendIntentError::InputCount(0))
        ));
        assert!(matches!(
            refused(&|i| i.input_global_indices = (0..=u64::from(MAX_INPUTS)).collect()),
            Some(SpendIntentError::InputCount(n)) if n == MAX_INPUTS as usize + 1
        ));
        assert!(matches!(
            refused(&|i| {
                i.recipients = (0..=MAX_RECIPIENTS)
                    .map(|k| IntentRecipient {
                        address: vec![u8::try_from(k).unwrap()],
                        amount: AtomicUnits::from_raw(1),
                    })
                    .collect();
            }),
            Some(SpendIntentError::RecipientCount(n)) if n == MAX_RECIPIENTS as usize + 1
        ));
        assert!(matches!(
            refused(&|i| i.recipients[0].address = vec![0; MAX_ADDRESS_LEN as usize + 1]),
            Some(SpendIntentError::AddressTooLong(n)) if n == MAX_ADDRESS_LEN as usize + 1
        ));
    }

    #[test]
    fn validate_temporal_passes() {
        make_test_intent()
            .validate_temporal(950, &[0xCC; 32])
            .unwrap();
    }

    /// The window is CEN-I11's, from the connecting height `tip + 1`: with
    /// the reference at 900, tips 904 through 999 pass. 903 is too fresh;
    /// 1000 is the deadline passed, since no block above 1000 can list the
    /// spend. A reference above the tip is "not yet", never "expired".
    #[test]
    fn validate_temporal_is_the_consensus_window() {
        let intent = make_test_intent();
        let at = |tip: u64| intent.validate_temporal(tip, &[0xCC; 32]);
        let min = shekyl_curve_tree::REFERENCE_BLOCK_MIN_AGE.to_raw();
        let max = shekyl_curve_tree::REFERENCE_BLOCK_MAX_AGE.to_raw();
        let newest_tip = 900 + min - 1;
        let last_tip = 900 + max - 1;
        assert!(matches!(
            at(newest_tip - 1),
            Err(SpendIntentError::RefBlockTooFresh { .. })
        ));
        for tip in newest_tip..=last_tip {
            assert!(at(tip).is_ok(), "tip {tip}");
        }
        assert!(matches!(
            at(last_tip + 1),
            Err(SpendIntentError::RefBlockTooStale { .. })
        ));
        assert!(matches!(
            at(899),
            Err(SpendIntentError::RefBlockTooFresh { .. })
        ));
        assert!(matches!(
            at(0),
            Err(SpendIntentError::RefBlockTooFresh { .. })
        ));
    }

    #[test]
    fn validate_temporal_rejects_ref_block_hash_mismatch() {
        assert!(matches!(
            make_test_intent().validate_temporal(950, &[0xFF; 32]),
            Err(SpendIntentError::RefBlockHashMismatch { .. })
        ));
    }

    #[test]
    fn consensus_constants_match_baselines() {
        assert_eq!(CT_TYPE_FCMP_PLUS_PLUS_PQC, 1);
    }

    #[test]
    fn max_inputs_is_the_consensus_cap() {
        assert_eq!(
            MAX_INPUTS as usize,
            shekyl_wire::transaction::MAX_FCMP_INPUTS,
            "an intent's input cap drifted from the consensus cap (CEN-I4)"
        );
    }

    #[test]
    fn max_recipients_is_the_output_cap() {
        assert_eq!(
            MAX_RECIPIENTS as usize,
            shekyl_wire::transaction::MAX_OUTPUTS,
            "an intent's recipient cap drifted from the consensus output cap"
        );
    }

    #[test]
    fn wire_ct_type_matches_consensus_authority() {
        // Tripwire on the canonical FCMP++ ct-type wire value: if anyone edits
        // `shekyl_wire::transaction::CT_TYPE_FCMP` (the genesis dense ct tag, `1`)
        // without also updating `config/consensus_constants.json`, this test fires.
        assert_eq!(
            shekyl_wire::transaction::CT_TYPE_FCMP,
            CT_TYPE_FCMP_PLUS_PLUS_PQC,
            "shekyl-wire CT_TYPE_FCMP wire value drifted from \
             config/consensus_constants.json"
        );
    }

    #[test]
    fn validate_balance_passes() {
        make_test_intent()
            .validate_balance(&[AtomicUnits::from_raw(210), AtomicUnits::from_raw(100)])
            .unwrap();
    }

    #[test]
    fn validate_balance_rejects_mismatch() {
        assert!(matches!(
            make_test_intent()
                .validate_balance(&[AtomicUnits::from_raw(100), AtomicUnits::from_raw(100)]),
            Err(SpendIntentError::BalanceMismatch { .. })
        ));
    }

    #[test]
    fn chain_state_fingerprint_deterministic() {
        let fp = ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![42, 99],
            input_eligible_heights: vec![800, 850],
            input_amounts: vec![AtomicUnits::from_raw(100), AtomicUnits::from_raw(200)],
        };
        assert_eq!(fp.compute(), fp.compute());
    }
}
