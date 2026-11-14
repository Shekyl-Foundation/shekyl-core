// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one member brings to a ceremony: [`SigningContext`], everything it
//! derives from the intent and its own ledger (R-7), and, for the proposer
//! alone, [`ProposerInputs`].
//!
//! The intent is the only input a signer trusts. Every value here is the
//! member's own: the spent outputs as its scan recovered them, the
//! rerandomization seeds and pseudo-out blinds derived from the intent's
//! `kem_randomness_seed` (slice 4a derives them under the reserved labels,
//! `PQC_MULTISIG.md` §9.5; this slice's tests build them directly), and
//! the unsigned transaction its own construction yields. Nothing another
//! member sends enters this type.

use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_fcmp::frost_sal::{
    threshold_keys, Ed25519T, FrostKeyError, FrostSalError, SalSigningParams, SpentOutput,
    ThresholdKeys, RERANDOMIZATION_SEED_LEN,
};
use shekyl_fcmp::proof::ProveInputLeafChunk;
use shekyl_network::NetworkId;
use shekyl_types::{BlockHash, CurveTreeRoot, KeyImage, TxSignableHash};
use shekyl_wire::{Ct, CtBase, Input, Transaction, TxPrefix};
use zeroize::Zeroizing;

use crate::invariants::ValidatedIntent;
use crate::member_file::MemberFile;

/// One spent input, as this member knows it.
pub struct InputContext {
    /// The output's key `O`.
    pub output_key: [u8; 32],
    /// The output's commitment `C`.
    pub commitment: [u8; 32],
    /// `x = ho + b`, group-plaintext.
    pub spend_scalar: Zeroizing<[u8; 32]>,
    /// The output's `y_kem`.
    pub y_kem: Zeroizing<[u8; 32]>,
    /// The output's commitment mask `z`.
    pub commitment_mask: Zeroizing<[u8; 32]>,
    /// The input's pseudo-out blind `a`, derived from the intent.
    pub pseudo_out_blind: Zeroizing<[u8; 32]>,
    /// The input's rerandomization seed, derived from the intent.
    pub rerandomization_seed: Zeroizing<[u8; RERANDOMIZATION_SEED_LEN]>,
    /// The input's key image.
    pub key_image: KeyImage,
    /// The committed form the output's leaf binds (`0x02 ‖ n ‖ m ‖ h_1 … h_n`).
    pub committed_form: MultisigCommittedForm,
    /// This member's own `0x0D` X25519 ciphertext for the output.
    pub own_x25519_ct: [u8; 32],
    /// This member's own `0x0D` ML-KEM-768 ciphertext for the output.
    pub own_ml_kem_ct: Vec<u8>,
}

impl InputContext {
    /// The input's signing parameters, built from this member's own values.
    /// Every signer builds the same value from the same intent.
    pub(crate) fn params(
        &self,
        signable: TxSignableHash,
    ) -> Result<SalSigningParams, FrostSalError> {
        SalSigningParams::new(
            &self.rerandomization_seed,
            &SpentOutput {
                output_key: &self.output_key,
                commitment: &self.commitment,
                spend_scalar: &self.spend_scalar,
                y_kem: &self.y_kem,
                commitment_mask: &self.commitment_mask,
            },
            &self.pseudo_out_blind,
            signable,
        )
    }
}

/// The transaction before any proof or authorization: the prefix and the
/// committed base, as this member's construction yields them from the
/// intent. Its hash is the message every proof and signature is over.
#[derive(Clone, Debug)]
pub struct UnsignedSpend {
    /// The prefix: the inputs' key images, the outputs, `tx_extra`.
    pub prefix: TxPrefix,
    /// The fee, atomic units.
    pub fee: u64,
    /// The reference block.
    pub reference_block: BlockHash,
    /// The committed base: output commitments and encrypted fields.
    pub base: CtBase,
}

/// Why a member's context cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// This member is not one of the intent's signers.
    #[error("this member is not a signer of the intent")]
    NotASigner,
    /// The context's inputs are not the intent's.
    #[error("the context has {got} inputs; the intent spends {expected}")]
    InputCount { expected: usize, got: usize },
    /// The unsigned prefix's inputs are not the context's key images, in
    /// order, as plain spend inputs.
    #[error("the unsigned prefix does not spend the context's inputs in order")]
    PrefixInputs,
    /// The unsigned fee is not the intent's.
    #[error("the unsigned fee is not the intent's")]
    Fee,
    /// An input's committed form is not for this group.
    #[error("input {input}'s committed form is not for this group")]
    CommittedForm { input: usize },
    /// This member's key share does not load.
    #[error("this member's key share does not load: {0}")]
    Keys(FrostKeyError),
    /// An input's parameters do not build, or the keys do not open it.
    #[error("input {input}'s signing parameters do not build: {source}")]
    Params { input: usize, source: FrostSalError },
}

/// What one member signs from.
pub struct SigningContext<'a> {
    pub(crate) member: &'a MemberFile,
    pub(crate) network_id: NetworkId,
    pub(crate) keys: ThresholdKeys<Ed25519T>,
    pub(crate) intent: ValidatedIntent,
    pub(crate) inputs: Vec<InputContext>,
    pub(crate) unsigned: UnsignedSpend,
    pub(crate) tree_root: CurveTreeRoot,
    pub(crate) fcmp_layers: u8,
    pub(crate) tx_signable: TxSignableHash,
}

impl<'a> SigningContext<'a> {
    /// Build `member`'s context for `intent`.
    ///
    /// Checks what can be checked without the derivation itself (slice
    /// 4a's): this member signs the intent; one input context per intent
    /// input; the unsigned prefix spends exactly the contexts' key images,
    /// in order; the unsigned fee is the intent's; every committed form is
    /// for this group's size; this member's share loads; and every input's
    /// parameters build and are opened by this member's keys.
    ///
    /// # Errors
    ///
    /// The first [`ContextError`] that holds.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct part of the member's own view"
    )]
    pub fn new(
        member: &'a MemberFile,
        network_id: NetworkId,
        intent: ValidatedIntent,
        inputs: Vec<InputContext>,
        unsigned: UnsignedSpend,
        tree_root: CurveTreeRoot,
        fcmp_layers: u8,
    ) -> Result<Self, ContextError> {
        if !intent.intent().signers.contains(&member.member_index()) {
            return Err(ContextError::NotASigner);
        }
        let expected = intent.intent().input_global_indices.len();
        if inputs.len() != expected {
            return Err(ContextError::InputCount {
                expected,
                got: inputs.len(),
            });
        }
        let spends_in_order = unsigned.prefix.inputs.len() == inputs.len()
            && unsigned
                .prefix
                .inputs
                .iter()
                .zip(&inputs)
                .all(|(wire, ctx)| {
                    matches!(wire, Input::ToKey { amount: 0, key_offsets, key_image }
                    if key_offsets.is_empty() && key_image == ctx.key_image.as_bytes())
                });
        if !spends_in_order {
            return Err(ContextError::PrefixInputs);
        }
        if unsigned.fee != intent.intent().fee.to_raw() {
            return Err(ContextError::Fee);
        }
        let address = member.address();
        for (input, ctx) in inputs.iter().enumerate() {
            if ctx.committed_form.n_total() != address.n_total()
                || ctx.committed_form.m_required() != address.m_required()
            {
                return Err(ContextError::CommittedForm { input });
            }
        }
        let keys = threshold_keys(
            address.n_total(),
            address.m_required(),
            member.member_index(),
            member.y_share(),
            member.verification_shares(),
            address.y_group(),
        )
        .map_err(ContextError::Keys)?;
        let tx_signable = Transaction {
            prefix: unsigned.prefix.clone(),
            ct: Ct::Fcmp {
                fee: unsigned.fee,
                reference_block: unsigned.reference_block,
                base: unsigned.base.clone(),
                pqc_auths: Vec::new(),
                prunable: None,
            },
        }
        .tx_signable(&network_id);
        for (input, ctx) in inputs.iter().enumerate() {
            let params = ctx
                .params(tx_signable)
                .map_err(|source| ContextError::Params { input, source })?;
            shekyl_fcmp::frost_sal::check_keys_open(&params, &keys)
                .map_err(|source| ContextError::Params { input, source })?;
        }
        Ok(Self {
            member,
            network_id,
            keys,
            intent,
            inputs,
            unsigned,
            tree_root,
            fcmp_layers,
            tx_signable,
        })
    }

    /// The intent this context signs.
    #[must_use]
    pub fn intent(&self) -> &ValidatedIntent {
        &self.intent
    }

    /// The message every proof and signature of this spend is over.
    #[must_use]
    pub fn tx_signable(&self) -> TxSignableHash {
        self.tx_signable
    }

    /// The member whose context this is.
    #[must_use]
    pub fn member(&self) -> &MemberFile {
        self.member
    }

    pub(crate) fn params(&self, input: usize) -> SalSigningParams {
        self.inputs[input]
            .params(self.tx_signable)
            .expect("new() built every input's params")
    }
}

/// What the proposer alone needs to finish the transaction: each output's
/// amount and commitment mask (the range proof covers them), and each
/// input's path to the reference root (the membership proof).
pub struct ProposerInputs {
    /// Per output, in output order: `(amount, commitment mask)`.
    pub outputs: Vec<(u64, Zeroizing<[u8; 32]>)>,
    /// Per input, in input order: its leaf chunk and branch.
    pub leaf_chunks: Vec<ProveInputLeafChunk>,
}
